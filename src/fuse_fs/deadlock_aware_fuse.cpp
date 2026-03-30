#define FUSE_USE_VERSION 31
#define _FILE_OFFSET_BITS 64
#include <fuse.h>
#include<unistd.h>
#include<iostream>
#include<chrono>

using namespace std;


extern pid_t ML_DAEMON_PID;
extern int check_ipc_for_response();

int query_ml_daemon_with_timeout(const char* buf, size_t size, int timeout_ms){
    auto start_time = std::chrono::steady_clock::now();

    while(true){

        int ml_response = check_ipc_for_response();

        if(ml_response == 0 || ml_response == 1){
            return ml_response;
        }
        
        auto current_time = std::chrono::steady_clock::now();
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time).count();

        if(elapsed > timeout_ms){
            cerr<<"[Critical]! ML Daemon timeout. Aborting Circular wait to prevent deadlock."<<endl;
            return -1;
        }

        usleep(1000);
    }
}

static int ransomeware_proof_write(const char* path, const char* buf, size_t size, off_t offset, struct fuse_file_info *fi) {
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