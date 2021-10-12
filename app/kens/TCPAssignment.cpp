/*
 * E_TCPAssignment.cpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#include "TCPAssignment.hpp"
#include <E/E_Common.hpp>
#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_NetworkUtil.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_Packet.hpp>
#include <cerrno>

namespace E {


TCPAssignment::TCPAssignment(Host &host)
    : HostModule("TCP", host), RoutingInfoInterface(host),
      SystemCallInterface(AF_INET, IPPROTO_TCP, host),
      TimerModule("TCP", host){}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {} // TODO 1

void TCPAssignment::finalize() {} // TODO 2

void TCPAssignment::systemCallback(UUID syscallUUID, int pid,
                                   const SystemCallParameter &param) {

  // Remove below
  (void)syscallUUID;
  (void)pid;

  switch (param.syscallNumber) {
  case SOCKET:
    this->syscall_socket(syscallUUID, pid, param.param1_int,
    param.param2_int, param.param3_int);
    break;
  case CLOSE:
    this->syscall_close(syscallUUID, pid, param.param1_int);
    break;
  case READ:
    this->syscall_read(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case WRITE:
    this->syscall_write(syscallUUID, pid, param.param1_int, param.param2_ptr,
    param.param3_int);
    break;
  case CONNECT:
    this->syscall_connect(syscallUUID, pid, param.param1_int,
          static_cast<struct sockaddr*>(param.param2_ptr),
    (socklen_t)param.param3_int);
    break;
  case LISTEN:
    this->syscall_listen(syscallUUID, pid, param.param1_int,
    param.param2_int);
    break;
  case ACCEPT:
    this->syscall_accept(syscallUUID, pid, param.param1_int,
          static_cast<struct sockaddr*>(param.param2_ptr),
          static_cast<socklen_t*>(param.param3_ptr));
    break;
  case BIND:
    this->syscall_bind(syscallUUID, pid, param.param1_int,
          static_cast<struct sockaddr *>(param.param2_ptr),
          (socklen_t) param.param3_int);
    break;
  case GETSOCKNAME:
    this->syscall_getsockname(syscallUUID, pid, param.param1_int,
          static_cast<struct sockaddr *>(param.param2_ptr),
          static_cast<socklen_t*>(param.param3_ptr));
    break;
  case GETPEERNAME:
    this->syscall_getpeername(syscallUUID, pid, param.param1_int,
          static_cast<struct sockaddr *>(param.param2_ptr),
          static_cast<socklen_t*>(param.param3_ptr));
    break;
  default:
    assert(0);
  }
} 

void TCPAssignment::packetArrived(std::string fromModule, Packet &&packet) {
  // Remove below
  uint32_t srcip, destip, seqnum, acknum;
  uint16_t srcport, destport, checksum;

  int ip_header = 14;
  int tcp_header = ip_header + 12;

  packet.readData(ip_header, &srcip,4);
  packet.readData(ip_header + 4, &destip, 4);
  packet.readData(tcp_header, &srcport, 2);
  packet.readData(tcp_header+2, &destport, 2);
  packet.readData(tcp_header+4, &seqnum, 4);
  packet.readData(tcp_header+8, &acknum, 4);
  packet.readData(tcp_header+32, &checksum, 2);
//TODO: flag 어떻게 하지 ? 46byte+ headlen 4+ not used 6 + flags 6; 


} // TODO 3

void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
} // TODO 4                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                    


// SystemCallback - TODO 5

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol){
  //TODO : map 어디서 initialize ??
    PFDtable *pfd;
    int fd = this -> createFileDescriptor(pid);

    socket *sock = new socket;
    sock -> domain = domain;
    sock -> protocol = protocol;

    if(this->pfdmap.find(pid) == this->pfdmap.end()){
      pfd = new PFDtable;
      pfd -> pid = pid;
      pfdmap[pid] = pfd; 
    }
    
    pfd = this->pfdmap[pid];
    pfd->fdmap.insert({fd, sock});
    
    this->returnSystemCall(syscallUUID, fd); 

}

void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
  this->portmap.erase(this->pfdmap[pid]->fdmap[sockfd]->src_port);
  this->removeFileDescriptor(pid,sockfd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, int count){

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void *buf, int count){

}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t addrlen){
 
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){

}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen){

}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen){
  // struct socket 에 addr 저장하기!;
      PFDtable *pfd;
      socket *sock;
      in_port_t port;
      in_addr_t ipaddr;

      if(this->pfdmap.find(pid) == this->pfdmap.end()) //pid 없으면 error
        this->returnSystemCall(syscallUUID, -1);

      pfd = this->pfdmap[pid];

      if(pfd->fdmap.find(fd) == pfd->fdmap.end()) //fd 없으면 error
        this->returnSystemCall(syscallUUID, -1);

      sock = pfd->fdmap[fd]; 

      if(sock->bind == 1) // socket already bound -> error
        this->returnSystemCall(syscallUUID, -1);

      sock->sin_family = AF_INET;
      memcpy(&port, addr->sa_data, 2);
      memcpy(&ipaddr, addr->sa_data+2, 4);

      if(this -> portmap.find(port) != this -> portmap.end()){ // port가 이미 쓰이는지
        if(this->portmap[port] != pid) // 다른 process에서 이미 쓰이는 port -> error
          this -> returnSystemCall(syscallUUID, -1);
        if(((this->pfdmap[pid])->portippair).find({port, ipaddr}) != (this->pfdmap[pid])->portippair.end()) // 같은 process 같은 (ip, port) -> error
          this -> returnSystemCall(syscallUUID, -1);
        if(((this->pfdmap[pid])->portippair).find({port, INADDR_ANY}) != (this->pfdmap[pid])->portippair.end()) // 같은 process 같은 (ip, port) -> error
          this -> returnSystemCall(syscallUUID, -1);
        if((this -> portmap[port] == pid) && (ipaddr == INADDR_ANY))
          this -> returnSystemCall(syscallUUID, -1);
        // TODO: (ip, port) 들어오고 (ANY, port) 들어오는 경우도 고려해줘야 하지 않나?
      }

      sock->src_port = port;
      sock->src_ipaddr = ipaddr;

      sock->src_addr = addr;
      sock->bind = 1;

      this->pfdmap[pid]->portippair.insert({port, ipaddr});
      this->portmap.insert({port, pid});

      this->returnSystemCall(syscallUUID, 0);
      
    
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen){
      if(pfdmap.find(pid) == pfdmap.end()) //pid 없는 경우
        this -> returnSystemCall(syscallUUID, -1);
      
      if((pfdmap[pid] -> fdmap).find(fd) == (pfdmap[pid] -> fdmap).end()) // fd 없는 경우
        this -> returnSystemCall(syscallUUID, -1);
      
      sockaddr* getaddr = pfdmap[pid] -> fdmap[fd] -> src_addr; 
      addr->sa_family = AF_INET;
      memcpy(&addr->sa_data, getaddr->sa_data, 14);
      addrlen = (socklen_t *)sizeof(* addr);

      this -> returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen){

}

} // namespace E