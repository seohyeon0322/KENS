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
      TimerModule("TCP", host) {}

TCPAssignment::~TCPAssignment() {}

void TCPAssignment::initialize() {} // TODO 1

void TCPAssignment::finalize() {
  // this->pfdmap.clear();
  // this->portmap.clear();

  // this->clientfd_set.clear();
  // this->connfd_set.clear();
  
} // TODO 2

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
  in_addr_t srcip, destip, seqnum, acknum;
  in_port_t srcport, destport;
  uint16_t checksum, checksum_computed, checksum_made;
  uint8_t flag;
  size_t packet_size = 54, length = 20; // 기본 기준 length
  uint8_t tcp_seg[length], checksum_making[length] = {0,};
  Packet pkt (packet_size);

  // Extract Information of the packet

  int ip_header = 26;
  int tcp_header = 34;
  

  // std::cout << "packet arrived" << std::endl;
  packet.readData(ip_header, &srcip, 4);
  packet.readData(ip_header+4, &destip, 4);
  packet.readData(tcp_header, &srcport, 2);
  packet.readData(tcp_header+2, &destport, 2);
  packet.readData(tcp_header+4, &seqnum, 4);
  packet.readData(tcp_header+8, &acknum, 4);
  packet.readData(tcp_header+13, &flag, 1);
  packet.readData(tcp_header+16, &checksum, 2);
  packet.readData(tcp_header, &tcp_seg, length);

  // srcip = htonl(srcip);
  // destip = htonl(destip);
  // srcport = htons(srcport);
  // destport = htons(destport);

  // make checksum part -> zero
  // compare checksum and calculated checksum
  tcp_seg[16] = 0;
  tcp_seg[17] = 0;
  checksum_computed = NetworkUtil::tcp_sum(srcip, destip, tcp_seg, length);
  checksum_computed = ~ checksum_computed;
  checksum_computed = htons(checksum_computed);
  if((checksum ^ checksum_computed) != 0)
    return;

  // make checksum part -> zero
  // compare checksum and calculated checksum
  tcp_seg[16] = 0;
  tcp_seg[17] = 0;
  checksum_computed = NetworkUtil::tcp_sum(srcip, destip, tcp_seg, length);
  checksum_computed = ~ checksum_computed;
  checksum_computed = htons(checksum_computed);
  if((checksum ^ checksum_computed) != 0)
    return;

  // TODO: flag 따라 처리
  // TODO: 원래 state 고려 안하고 맞다고 생각하고 짜놨는데, state 고려하기 (e.g. SYN_SENT 였을 때만 SYN_ACK 받아 처리)
  if (flag == TH_SYN){ //SYN
  // 1. using packet's destip/port, find listening socket.
  // 2. put addrinfo in pending_queue. 
    std::unordered_map<socket*, pending_backlog* >::iterator it;
    //
    sockaddrinfo* clisockaddr = new sockaddrinfo;
    clisockaddr->src_port = srcport;
    clisockaddr->src_ipaddr = srcip;
    clisockaddr->dest_port = destport;
    clisockaddr->dest_ipaddr = destip;

    //finding listensooket
    for(it = listenfd_map.begin(); it!=listenfd_map.end(); ++it){ //clientfd socket state 바꾸기
      socket* listensocket = it -> first; 
      if(((listensocket->sockaddrinfo.src_port == destport) && (listensocket->sockaddrinfo.src_ipaddr == destip))
      ||(listensocket -> sockaddrinfo.src_ipaddr == 0)){ //listensocket we want to find.
        it->second->pending_queue.push(clisockaddr); //push addrinfo in pending_queue

        // syn ack 보내기
        memcpy(&acknum, &seqnum, 4);
        acknum++; // acknum = seqnum + 1
        seqnum = 305894; // TODO: how to select (Randomly)
        flag = (TH_SYN|TH_ACK);
        pkt.writeData(ip_header, &destip, 4); // src <-> dest (server2client니까)
        pkt.writeData(ip_header+4, &srcip, 4);

        // make checksum
        pkt.writeData(tcp_header, &destport, 2);
        pkt.writeData(tcp_header+2, &srcport, 2);
        pkt.writeData(tcp_header+4, &seqnum, 4);
        pkt.writeData(tcp_header+8, &acknum, 4);
        pkt.writeData(tcp_header+13, &flag, 1);
        pkt.readData(tcp_header, &checksum_making, 14);
        checksum_made = htons(~ NetworkUtil::tcp_sum(destip, srcip, checksum_making, length));
        // warning: pkt can be overwritten.

        struct tcphdr tcphdr;
          tcphdr.th_sport = destport;
          tcphdr.th_dport = srcport;
          tcphdr.th_seq = seqnum;
          tcphdr.th_ack = acknum;
          tcphdr.th_flags = flag;
          tcphdr.th_sum = checksum_made;
          tcphdr.th_off = (uint8_t)5;

        pkt.writeData(tcp_header, &tcphdr, 20);

        void *temp_buf = malloc(pkt.getSize());
        pkt.readData(0, temp_buf, pkt.getSize());

        memcpy(&tcphdr, temp_buf+34, 20);

        this->sendPacket("IPv4", std::move(pkt));
        // std:: cout<< "after send packet" << std::endl;

        }
      }
    }else if (flag == (TH_SYN|TH_ACK)){ //SYN+ACK
      // cleintfdmap에서 socket 데려오기
      // TODO: state SYN_SENT인지 확인
      
      for(std::set<socket*>::iterator it = connfd_set.begin(); it!=connfd_set.end(); ++it){
        socket* sock = *it;  
        if((sock->sockaddrinfo.src_port == destport) && (sock->sockaddrinfo.src_ipaddr == destip) 
        && (sock->sockaddrinfo.dest_port == srcport) && (sock->sockaddrinfo.dest_ipaddr == srcip)){
            if(sock->state == TCP_SYN_SENT){ //client_socket이 synsent인 경우에만 ack 보내기
            memcpy(&acknum, &seqnum, 4);
            acknum++; // acknum = seqnum + 1
            seqnum = 305894; // TODO: how to select????
            flag = TH_ACK; // 16
            pkt.writeData(ip_header, &destip, 4); // src <-> dest (server2client니까)
            pkt.writeData(ip_header+4, &srcip, 4);

            // make checksum
            pkt.writeData(tcp_header, &destport, 2);
            pkt.writeData(tcp_header+2, &srcport, 2);
            pkt.writeData(tcp_header+4, &seqnum, 4);
            pkt.writeData(tcp_header+8, &acknum, 4);
            pkt.writeData(tcp_header+13, &flag, 1);
            pkt.readData(tcp_header, &checksum_making, 14);
            checksum_made = htons(~ NetworkUtil::tcp_sum(destip, srcip, checksum_making, length));
            // warning: pkt can be overwritten.

            struct tcphdr tcphdr;
              tcphdr.th_sport = destport;
              tcphdr.th_dport = srcport;
              tcphdr.th_seq = seqnum;
              tcphdr.th_ack = acknum;
              tcphdr.th_flags = flag;
              tcphdr.th_sum = checksum_made;
              tcphdr.th_off = (uint8_t)5;

            pkt.writeData(tcp_header, &tcphdr, 20);

            void *temp_buf = malloc(pkt.getSize());
            pkt.readData(0, temp_buf, pkt.getSize());

            memcpy(&tcphdr, temp_buf+34, 20);

            this->sendPacket("IPv4", std::move(pkt));
      
            // state -> Established & Connect Return
            sock -> state = TCP_ESTABLISHED;
            returnSystemCall(sock -> SyscallUUID, 0);
          }
          }
        }
    }

//   }else if (flag == TH_ACK){
//       // Socket 찾기
//       for(std::set<socket*>::iterator it = connfd_set.begin(); it!=connfd_set.end(); ++it){
//         socket* sock = *it;  
//         if((sock->sockaddrinfo.src_port == destport) && (sock->sockaddrinfo.src_ipaddr == destip) 
//         && (sock->sockaddrinfo.dest_port == srcport) && (sock->sockaddrinfo.dest_ipaddr == srcip)){
//           if(sock->state == TCP_SYN_RECV){
//             accepted_queue.push(sock);

//             // TODO: Established & Accpet Return
//             sock->state = TCP_ESTABLISHED;
//             pending_queue.pop();
//             returnSystemCall(sock->SyscallUUID, 0);
//           }
//       // TODO: Accepted queue + pending Queue에서는 언제 삭제함?
//       }
//       }
  } // TODO 3
  
void TCPAssignment::timerCallback(std::any payload) {
  // Remove below
  (void)payload;
} // TODO 4

// SystemCallback - TODO5

void TCPAssignment::syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol){
  //TODO : map 어디서 initialize ??
    PFDtable *pfd;
    int fd = this -> createFileDescriptor(pid);

    socket *sock = new socket;
    // sock = (socket *)malloc(sizeof(socket));  // how to initialize?
    sock -> fd = fd ; 
    sock -> sin_family = AF_INET;
    sock -> domain = domain;
    sock -> protocol = protocol;

    if(this->pfdmap.find(pid) == this->pfdmap.end()){
      struct PFDtable *pfd = new PFDtable;
      pfd -> pid = pid;
      pfdmap[pid] = pfd; 
    }
    
    pfd = this->pfdmap[pid];
    pfd->fdmap.insert({fd, sock});
    
    this->returnSystemCall(syscallUUID, fd); 

}


void TCPAssignment::syscall_close(UUID syscallUUID, int pid, int sockfd){
  this->portmap.erase(this->pfdmap[pid]->fdmap[sockfd]->sockaddrinfo.src_port);
  // delete(this->pfdmap[pid]->fdmap[sockfd]);
  this->removeFileDescriptor(pid,sockfd);
  this->returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_read(UUID syscallUUID, int pid, int fd, void *buf, int count){

}

void TCPAssignment::syscall_write(UUID syscallUUID, int pid, int fd, void *buf, int count){

}

void TCPAssignment::syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t addrlen){

  socket *sock;
  ipv4_t dest_ip; // uint8_t array ipv4_t에서 바꿈
  size_t packet_size = 100, length = 20;
  Packet pkt (packet_size);
  uint8_t flag = TH_SYN;
  uint16_t checksum_made;
  uint32_t ack_num = 0, seq_num = 150000; // TODO: How to Select? Random?
  uint8_t checksum_making[length] = {0,};

  if(this->pfdmap.find(pid) == this->pfdmap.end()){ // nonexisting pid -> error
    return;
  }else if(this->pfdmap[pid]->fdmap.find(fd) == this->pfdmap[pid]->fdmap.end()){ // nonexisting fd -> error
    return;
  }

  sock = this->pfdmap[pid]->fdmap[fd];
  
  if(sock->state != TCP_LISTEN) // weird client socket -> error
    return;

  sockaddrinfo addrinfo = sock->sockaddrinfo;

  sock -> SyscallUUID = syscallUUID; // store UUID in socket for later return

  // Given destination
  memcpy(&(addrinfo.dest_port), addr->sa_data, 2);
  memcpy(&(addrinfo.dest_ipaddr), addr->sa_data+2, 4);

  // TODO: ip address 형식들 정리/변환하기 - ipv4_t, uint64_t, uint32_t, in_addr_t, ...
  // Networkutil 함수 중, uint64_t <-> uint8_t array 있음

  // ipv4_t(uint8_t array) destination ip 만들어주기 for getRoutingTable


  memcpy(&dest_ip, addr->sa_data+2, 1);
  memcpy(&dest_ip+1, addr->sa_data+3, 1);
  memcpy(&dest_ip+2, addr->sa_data+4, 1);
  memcpy(&dest_ip+3, addr->sa_data+5, 1);

  // TODO: Select local IP, port
  // TODO: random number - port num 어디서부터 쓸 수 있음? How to Select?
  addrinfo.src_port = htons(9999);
  // TODO: +) htonl?


  int port = this->getRoutingTable(dest_ip);
  ipv4_t sourceip = this->getIPAddr(port).value();
  sock->sockaddrinfo.src_ipaddr = NetworkUtil::arrayToUINT64(sourceip);

  // sock -> src_addr 채우기(sockaddr*)
  sock->sin_family = AF_INET;
  sock->src_addr->sa_family = AF_INET;
  memcpy(sock->src_addr->sa_data, &(addrinfo.src_port), 2);
  memcpy(sock->src_addr->sa_data+2, &(addrinfo.src_ipaddr), 4);


  sock -> bind = 1; // bound
  sock -> state = TCP_SYN_SENT; // state 변환

  this->clientfd_set.insert(sock);


  // TODO: syn packet 보내기 - ip address 형식 확인, checksum 만들어서 넣어주기
  pkt.writeData(0, &(addrinfo.src_ipaddr), 4);
  pkt.writeData(4, &(addrinfo.dest_ipaddr), 4);
  pkt.writeData(8, &(addrinfo.src_port), 2);
  pkt.writeData(10, &(addrinfo.dest_port), 2);
  pkt.writeData(12, &seq_num, 4); 
  pkt.writeData(16, &ack_num, 4);
  pkt.writeData(21, &flag, 1); // 2

  // make checksum
  pkt.readData(8, &checksum_making, 14);
  checksum_made = htons(~ NetworkUtil::tcp_sum(addrinfo.src_ipaddr, addrinfo.dest_ipaddr, checksum_making, length));

  pkt.writeData(24, &checksum_made, 2);
  sendPacket("IPv4", std::move(pkt));

}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){
// 1. make listenfd_map
// 2. change socket's state to LISTEN

  socket* listensock = this->pfdmap[pid]->fdmap[fd];
  pending_backlog* pending_backlog_struct = new pending_backlog;
  pending_backlog_struct -> backlog = backlog;
  listensock -> state = TCP_LISTEN;
  listenfd_map[listensock] = pending_backlog_struct;
  this -> returnSystemCall(syscallUUID, 0);
  
  //TODO: handling error
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen){
  //connfdmap에 넣어주기
  struct socket * listensock = this->pfdmap[pid]->fdmap[fd];
  struct socket * connsock  = new socket;
  struct sockaddrinfo listenaddrinfo = listensock->sockaddrinfo;
  //TODO: connsock fd 값 만들어주기 ..... fighitng seohyeon ...
  in_port_t port; //TODO : type 맞추기
  in_addr_t ipaddr;
  memcpy(&port, addr->sa_data, 2);
  memcpy(&ipaddr, addr->sa_data+2, 4);


  //   for(std::set<socket*>::iterator it = clientfd_set.begin(); it!=clientfd_set.end(); ++it){
  //   socket* connsock = *it;  
  //   if((connsock->sockaddrinfo.src_port == destport) && (connsock->sockaddrinfo.src_ipaddr == destip) 
  //   && (connsock->sockaddrinfo.dest_port == srcport) && (connsock->sockaddrinfo.dest_ipaddr == srcip)){

  //       sock->state = TCP_SYN_RECV;
  //   }
  // }

  int connfd = this -> createFileDescriptor(pid);
  PFDtable *pfd = this->pfdmap[pid];
  pfd->fdmap.insert({connfd, connsock});

  connsock -> fd = connfd;
  connsock -> SyscallUUID = syscallUUID;
  connsock -> domain = listensock -> domain;
  connsock -> protocol = listensock -> protocol;
  connsock -> sockaddrinfo.src_port = listenaddrinfo.src_port;
  connsock -> sockaddrinfo.src_ipaddr = listenaddrinfo.src_ipaddr;
  connsock -> bind = 1; 
  connsock -> sin_family = listensock -> sin_family;
  connsock-> sockaddrinfo.dest_port = port;
  connsock-> sockaddrinfo.dest_ipaddr = ipaddr;
  connsock->src_addr = listensock ->src_addr;
  connsock -> state = TCP_LISTEN;

  connfd_set.insert(connsock);
}

void TCPAssignment::syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen){
  // struct socket 에 addr 저장하기!;
      PFDtable *pfd;
      socket *sock;
      in_port_t port;
      in_addr_t ipaddr;

      if(this->pfdmap.find(pid) == this->pfdmap.end()) {//pid 없으면 error
        this->returnSystemCall(syscallUUID, -1);
        return;
      }

      pfd = this->pfdmap[pid];

      if(pfd->fdmap.find(fd) == pfd->fdmap.end()){ //fd 없으면 error
        this->returnSystemCall(syscallUUID, -1);
        return;
      }

      sock = pfd->fdmap[fd]; 

      if(sock->bind == 1){ // socket already bound -> error
        this->returnSystemCall(syscallUUID, -1);
        return;
      }

      sock->sin_family = AF_INET;
      memcpy(&port, addr->sa_data, 2);
      memcpy(&ipaddr, addr->sa_data+2, 4); //debug: 여기서 ip_addr 0 나옴

      if(this -> portmap.find(port) != this -> portmap.end()){ // port가 이미 쓰이는지
        if(this->portmap[port] != pid) {// 다른 process에서 이미 쓰이는 port -> error
          this -> returnSystemCall(syscallUUID, -1);
          return;
        }
        if(((this->pfdmap[pid])->portippair).find({port, ipaddr}) != (this->pfdmap[pid])->portippair.end()) {// 같은 process 같은 (ip, port) -> error
          this -> returnSystemCall(syscallUUID, -1);
          return;
        }
        if(((this->pfdmap[pid])->portippair).find({port, INADDR_ANY}) != (this->pfdmap[pid])->portippair.end()){ // 같은 process 같은 (ip, port) -> error
          this -> returnSystemCall(syscallUUID, -1);
          return;
        }
        if((this -> portmap[port] == pid) && (ipaddr == INADDR_ANY)){
          this -> returnSystemCall(syscallUUID, -1);
          return;
        }
        // TODO: (ip, port) 들어오고 (ANY, port) 들어오는 경우도 고려해줘야 하지 않나?
      }

      sock->sockaddrinfo.src_port = port;
      sock->sockaddrinfo.src_ipaddr = ipaddr;
      sock->src_addr = addr;
      sock->bind = 1;


      this->pfdmap[pid]->portippair.insert({port, ipaddr});
      this->portmap.insert({port, pid});

      this->returnSystemCall(syscallUUID, 0);
      
    
}

void TCPAssignment::syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen){
      if(this->pfdmap.find(pid) == this->pfdmap.end()) {//pid 없는 경우
        this -> returnSystemCall(syscallUUID, -1);
        return;
      }
      if((this->pfdmap[pid] -> fdmap).find(fd) == (this->pfdmap[pid] -> fdmap).end()) {// fd 없는 경우
        this -> returnSystemCall(syscallUUID, -1);
        return;
      }
      sockaddr* getaddr = this->pfdmap[pid] -> fdmap[fd] -> src_addr; 
      addr->sa_family = AF_INET;
      memcpy(&addr->sa_data, getaddr->sa_data, 14);
      addrlen = (socklen_t *)sizeof(* addr);

      this -> returnSystemCall(syscallUUID, 0);
}

void TCPAssignment::syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen){

}

} // namespace E