#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64
#include <fuse.h>
#include<unistd.h>
#include<iostream>
#include<fstream>
#include<sys/socket.h>
#include<sys/un.h>
#include<chrono>

using namespace std;

const char *SOCKET_PATH = "/tmp/ransomeware_defense.lock";
pid_t ML_DAEMON_PID = 0;

extern int check_ipc_for_response();

void load_daemon_pid(){
    ifstream pid_file("tmp/ml_daemon.pid");
    if(pid_file.is_open()){
        pid_file >> ML_DAEMON_PID;
    }
}

int query_ml_daemon_with_timeout(const char* buf, size_t size, int timeout_ms){
    int sock = socket(AF_UNIX, SOCK_STREAM, 0);
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;


    // auto start_time = std::chrono::steady_clock::now();
    strncpy(addr.sun_path, SOCKET_PATH, sizeof(addr.sun_path) -1);

    if(connect(sock, (struct sockaddr*) & addr, sizeof(addr)) == -1){
        return -1;
    }

    send(sock, buf, size, 0);

    struct timeval tv; //timeval has two elements called tv_sec and tv_usec

    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);

    char response[2] = {0};

    int bytes_received = recv(sock, response, 1, 0);

    close(sock);

    if(bytes_received <= 0){
        cerr<<"[Critical] ML Daemon timeout!  Breaking wait to prevent deadlock."<<endl;

        return -1;
    }

    return (response[0] == '1') ? 1: 0;
    // while(true){

    //     int ml_response = check_ipc_for_response();

    //     if(ml_response == 0 || ml_response == 1){
    //         return ml_response;
    //     }
        
    //     auto current_time = std::chrono::steady_clock::now();
    //     auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count();

    //     if(elapsed > timeout_ms){
    //         cerr<<"[Critical]! ML Daemon timeout. Aborting Circular wait to prevent deadlock."<<endl;
    //         return -1;
    //     }

    //     usleep(1000);
    // }
}

static int ransomware_proof_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    pid_t calling_pid = fuse_get_context()->pid;

    if(calling_pid == ML_DAEMON_PID){
        return pwrite(fi->fh, buf, size, offset);
    }


    int verdict = query_ml_daemon_with_timeout(buf, size, 500);

    if(verdict == 1){
        cerr<<"[ALERT]! Ransomeware Detected on PID"<< calling_pid << "! Blocking write."<<endl;
        return -EACCES;
    }
    else if(verdict == -1) {
        cerr<<"[FAIL-SAFE] Timeout occured. Allowing write to prevent system Freeze"<<endl;
        return pwrite(fi->fh, buf, size, offset);
    }

    return pwrite(fi->fh, buf, size, offset);
}

static struct fuse_operations rfs_oper={};

int main(int argc, char* argv[]){
    rfs_oper.write = ransomware_proof_write;

    load_daemon_pid();

    cout<<"[*] Starting Deadlock Aware FUSE. Whitelisting PID: "<<ML_DAEMON_PID<<endl;

    return fuse_main(argc, argv, &rfs_oper, NULL);
}