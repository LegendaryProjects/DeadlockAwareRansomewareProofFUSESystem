#define FUSE_USE_VERSION 29
#define _FILE_OFFSET_BITS 64
#include <fuse.h>
#include<unistd.h>
#include<iostream>
#include<fstream>
#include<sys/socket.h>
#include<sys/un.h>
#include <dirent.h>
#include <fcntl.h>
#include <signal.h>
#include <sys/stat.h>
#include <cstring>
#include <cerrno>
#include <vector>
#include <string>
#include <algorithm>

using namespace std;

vector<string> HONEYFILES;

const char *SOCKET_PATH = "/tmp/ransomware_defense.sock";
const char *BACKING_STORE = "/tmp/backing_store";
pid_t ML_DAEMON_PID = 0;

extern int check_ipc_for_response();

void load_daemon_pid(){
    ifstream pid_file("/tmp/ml_daemon.pid");
    if(pid_file.is_open()){
        pid_file >> ML_DAEMON_PID;
    }
}

void load_honeyfiles() {
  ifstream h_file("/tmp/honeyfiles.txt");
  string line;
  if (h_file.is_open()) {
    while (getline(h_file, line)) {
      HONEYFILES.push_back(line);
    }
  }
}

 void log_edr_alert(const string& message) {
      ofstream log_file("/tmp/edr_alerts.log", ios_base::app);
      if (log_file.is_open()) {
          log_file << message << endl;
      }
  }


int query_ml_daemon_with_timeout(const char* path, const char* buf, size_t size, int timeout_ms){
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;

    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) -1);

    if(connect(sock, (struct sockaddr*) & addr, sizeof(addr)) == -1){
        return -1;
    }

    char path_header[512] = {0};
    strncpy(path_header, path, 511);
    if(send(sock, path_header, 512, 0) == -1) {
      close(sock);
      return -1;
    }

    if(send(sock, buf, size, 0) == -1) {
      close(sock);
      return -1;
    }

    struct timeval tv;
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
    char response[] = {0};
    int bytes_received = recv(sock, response, 1, 0);

    close(sock);

    if(bytes_received <= 0){
        cerr<<"[Critical] ML Daemon timeout!  Breaking wait to prevent deadlock."<<endl;
        return -1;
    }

    return (response[0] == '1') ? 1: 0;
}

void translate_path(char fpath[PATH_MAX], const char* path){
    strcpy(fpath,  BACKING_STORE);
    strncat(fpath, path, PATH_MAX - strlen(BACKING_STORE) - 1);
}


static int ransomware_proof_getattr(const char* path, struct stat* stbuf){
    char fpath[PATH_MAX];
    translate_path(fpath, path);

    int res = lstat(fpath, stbuf);
    if(res == -1){
        return -errno;
    }
    return 0;
}


//to be studied
static int ransomware_proof_readdir(const char* path, void* buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi){
    char fpath[PATH_MAX];
    translate_path(fpath, path);

    DIR *dp = opendir(fpath);
    if(dp == NULL){
        return -errno;
    }

    struct dirent *de;
    while((de = readdir(dp)) != NULL){
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        if(filler(buf, de->d_name, &st, 0))
            break;
    }

    closedir(dp);
    return 0;
}


static int ransomware_proof_open(const char *path, struct fuse_file_info *fi) {
    char fpath[PATH_MAX];
    translate_path(fpath, path);

    int fd = open(fpath, fi->flags);
    if(fd == -1){
        return -errno;
    }

    fi->fh = fd;
    return 0;
}


static int ransomware_proof_read(const char* path, char* buf, size_t size, off_t offset, struct fuse_file_info* fi){
    int res = pread(fi->fh, buf, size, offset);
    if(res == -1){
        res= -errno;
    }
    return res;
}


static int ransomware_proof_create(const char* path, mode_t mode , struct fuse_file_info *fi){
    char fpath[PATH_MAX];
    translate_path(fpath, path);

    int fd = open(fpath, fi->flags | O_CREAT, mode);

    if(fd == -1){
        return -errno;
    }
    fi->fh = fd;

    return 0;
}


int ransomware_proof_truncate(const char *path, off_t size) {
  return 0;
}


static int ransomware_proof_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    pid_t calling_pid = fuse_get_context()->pid;
    
    string current_path(path);
    if (find(HONEYFILES.begin(), HONEYFILES.end(), current_path) != HONEYFILES.end()) {
     string alert = "";
      alert += "[HONEYFILE TRIPWIRE] Rogue process touched '" + current_path + "'!\n";
      alert += "[MITIGATION] C++ Kernel Driver bypassed ML and executed SIGKILL.\n";
      
      log_edr_alert(alert); 
      if (calling_pid > 1 && calling_pid != getpid()) {
          kill(calling_pid, SIGKILL);
      }
      
      return -EACCES;
    }

    if(calling_pid == ML_DAEMON_PID){
        return pwrite(fi->fh, buf, size, offset);
    }

    int verdict = query_ml_daemon_with_timeout(path, buf, size, 2000);

    if(verdict == 1){
        cerr<<"\n\n[CRITICAL ALERT] Ransomware behavior detected!\n";
        cerr<<"[MITIGATION] Blocking write to file:" << path << "\n";
        cerr<<"[MITIGATION] Sending SIGKILL to terminate PID: " << calling_pid << "\n\n";

        int kill_status = kill(calling_pid, SIGKILL);
        
        if(kill_status == 0)
          cerr << "[SUCCESS] Rogue process " << calling_pid << " successfully terminated.\n";
        else
          cerr << "[WARNING] Failed to terminate process. It may already be dead or requires root.\n";

        return -EACCES;
    }

    else if(verdict == -1) {
        cerr<<"[FAIL-SAFE] Timeout occurred. Allowing write to prevent system Freeze"<<endl;
        return pwrite(fi->fh, buf, size, offset);
    }

    return pwrite(fi->fh, buf, size, offset);
}

static struct fuse_operations rfs_oper={};

int main(int argc, char* argv[]){
    rfs_oper.getattr = ransomware_proof_getattr;
    rfs_oper.readdir = ransomware_proof_readdir;
    rfs_oper.open = ransomware_proof_open;
    rfs_oper.read = ransomware_proof_read;
    rfs_oper.create = ransomware_proof_create;
    rfs_oper.truncate = ransomware_proof_truncate;
    rfs_oper.write = ransomware_proof_write;

    load_daemon_pid();
    load_honeyfiles();

    cout<<"[*] Starting Deadlock Aware FUSE. Whitelisting PID: "<<ML_DAEMON_PID<<endl;

    return fuse_main(argc, argv, &rfs_oper, NULL);
}