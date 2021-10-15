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
  in_addr_t srcip, destip; // TODO: typedef하면 그냥 쓰면 되나?
  in_port_t srcport, destport;
  uint16_t checksum, checksum_computed, checksum_made, urp, wnd;
  uint8_t flag, x2;
  size_t packet_size = 54, length = 20; // 기본 기준 length
  uint8_t tcp_seg[length] = {0,}, checksum_making[length] = {0,};
  // Packet pkt (packet_size), temp_pkt(packet_size); // TODO: packet random 으로 넣어지는데 초기화시켜야 됨?
  tcp_seq acknum = htonl(0), seqnum = htonl(0), tempnum = htonl(0); // TODO: 혹시 type의 문제인가?

  // Extract Information of the packet

  struct tcphdr tcphdr;


  int ip_header = 26;
  int tcp_header = 34;

  packet.readData(tcp_header, &tcphdr, 20);
  //  printf(" read: flag: %u, s: %u, a: %u, from: %u, to: %u \n", tcphdr.th_flags, ntohl(tcphdr.th_seq), ntohl(tcphdr.th_ack), ntohs(tcphdr.th_sport), ntohs(tcphdr.th_dport));
  
  packet.readData(ip_header, &srcip, 4);
  packet.readData(ip_header+4, &destip, 4);
  packet.readData(tcp_header, &srcport, 2);
  packet.readData(tcp_header+2, &destport, 2);
  packet.readData(tcp_header+4, &seqnum, 4);
  packet.readData(tcp_header+8, &acknum, 4);
  packet.readData(tcp_header+13, &flag, 1);
  packet.readData(tcp_header+16, &checksum, 2);
  packet.readData(tcp_header, &tcp_seg, length);
  // TODO: urgent point/ x2?
  packet.readData(tcp_header+18, &urp, 2);
  packet.readData(tcp_header+12, &x2, 1);
  packet.readData(tcp_header+14, &wnd, 2);

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
  // TODO: state 고려하기 (e.g. SYN_SENT 였을 때만 SYN_ACK 받아 처리)
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
    for(it = this->listenfd_map.begin(); it!=this->listenfd_map.end(); ++it){ //clientfd socket state 바꾸기
      socket* listensocket = it -> first; 
      if(((listensocket->sockaddrinfo.src_port == destport) && (listensocket->sockaddrinfo.src_ipaddr == destip))
      ||(listensocket -> sockaddrinfo.src_ipaddr == 0)){ //listensocket we want to find.
        int backlog = it->second->backlog;
        int queuesize = (int)it->second->pending_queue.size();
        if(queuesize < backlog){
        it->second->pending_queue.push(clisockaddr); //push addrinfo in pending_queue

        // syn ack 보내기
        // TODO: reserved set되어있고, urgent point
        // TODO: ack, syn 이상해 혹시 htonl이나 ntohl?
        tempnum = acknum;
        acknum = htonl(ntohl(seqnum) + 1);
        seqnum = tempnum;

        Packet pkt = packet.clone();
        Packet temp_pkt = packet.clone();

        flag = (TH_SYN|TH_ACK);
        pkt.writeData(ip_header, &destip, 4); // src <-> dest (server2client니까)
        pkt.writeData(ip_header+4, &srcip, 4);

        // make checksum
        temp_pkt.writeData(tcp_header, &destport, 2);
        temp_pkt.writeData(tcp_header+2, &srcport, 2);
        temp_pkt.writeData(tcp_header+4, &seqnum, 4);
        temp_pkt.writeData(tcp_header+8, &acknum, 4);
        temp_pkt.writeData(tcp_header+12, &x2, 1);
        temp_pkt.writeData(tcp_header+13, &flag, 1);
        temp_pkt.writeData(tcp_header+14, &wnd, 2);
        temp_pkt.writeData(tcp_header+18, &urp, 2);
        temp_pkt.readData(tcp_header, &checksum_making, 14);
        checksum_made = htons(~ NetworkUtil::tcp_sum(destip, srcip, checksum_making, length));
        // warning: pkt can be overwritten.
        // TODO: temp_pkt 써보자

        struct tcphdr tcphdr;
          tcphdr.th_sport = destport;
          tcphdr.th_dport = srcport;
          tcphdr.th_seq = seqnum;
          tcphdr.th_ack = acknum;
          tcphdr.th_flags = flag;
          tcphdr.th_sum = checksum_made;
          // TODO: th_off, th_x2, th_win, th_upr ??
          // tcphdr.th_x2 = x2;
          tcphdr.th_off = htonl(5);
          // tcphdr.th_urp = urp;
          tcphdr.th_win = wnd;
   printf("sent:flag: %u, s: %u, a: %u, from: %u, to: %u \n", tcphdr.th_flags, ntohl(tcphdr.th_seq), ntohl(tcphdr.th_ack), ntohs(tcphdr.th_sport), ntohs(tcphdr.th_dport));
        pkt.writeData(tcp_header, &tcphdr, 20);

        void *temp_buf = malloc(pkt.getSize());
        pkt.readData(0, temp_buf, pkt.getSize());

        // memcpy(&tcphdr, temp_buf+34, 20);

        this->sendPacket("IPv4", std::move(pkt));
        // std:: cout<< "after send packet" << std::endl;
        }
        }
      }
    }else if (flag == (TH_SYN|TH_ACK)){ //SYN+ACK
      // cleintfdmap에서 socket 데려오기
      // TODO: state SYN_SENT인지 확인
      
      for(std::set<socket*>::iterator it = connfd_set.begin(); it!=connfd_set.end(); ++it){
        socket* sock = *it;  
        if((sock->sockaddrinfo.src_port == destport) && (sock->sockaddrinfo.src_ipaddr == destip) 
        && (sock->sockaddrinfo.dest_port == srcport) && (sock->sockaddrinfo.dest_ipaddr == srcip)){
            if(sock->tcpinfo.tcpi_state == TCP_SYN_SENT){ //client_socket이 synsent인 경우에만 ack 보내기
            tempnum = acknum;
            acknum = htonl(ntohl(seqnum) + 1);
            seqnum = tempnum;
            
            flag = TH_ACK; // 16
            Packet pkt = packet.clone();
            Packet temp_pkt = packet.clone();

            pkt.writeData(ip_header, &destip, 4); // src <-> dest (server2client니까)
            pkt.writeData(ip_header+4, &srcip, 4);

            temp_pkt.writeData(tcp_header, &destport, 2);
            temp_pkt.writeData(tcp_header+2, &srcport, 2);
            temp_pkt.writeData(tcp_header+4, &seqnum, 4);
            temp_pkt.writeData(tcp_header+8, &acknum, 4);
            temp_pkt.writeData(tcp_header+12, &x2, 1);
            temp_pkt.writeData(tcp_header+13, &flag, 1);
            temp_pkt.writeData(tcp_header+14, &wnd, 2);
            temp_pkt.writeData(tcp_header+18, &urp, 2);
            temp_pkt.readData(tcp_header, &checksum_making, 14);
            checksum_made = htons(~ NetworkUtil::tcp_sum(srcip, destip, checksum_making, length));

            struct tcphdr tcphdr;
              tcphdr.th_sport = destport;
              tcphdr.th_dport = srcport;
              tcphdr.th_seq = seqnum;
              tcphdr.th_ack = acknum;
              tcphdr.th_flags = flag;
              tcphdr.th_sum = checksum_made;
              // TODO: th_off, th_x2, th_win, th_upr ??
              tcphdr.th_x2 = x2;
              tcphdr.th_off = 5;
              tcphdr.th_urp = urp;
              tcphdr.th_win = wnd;

            pkt.writeData(tcp_header, &tcphdr, 20);

            void *temp_buf = malloc(pkt.getSize());
            pkt.readData(0, temp_buf, pkt.getSize());

            memcpy(&tcphdr, temp_buf+34, 20);

            this->sendPacket("IPv4", std::move(pkt));
      
            // state -> Established & Connect Return
            sock -> tcpinfo.tcpi_state = TCP_ESTABLISHED;
            returnSystemCall(sock -> SyscallUUID, 0);
          }
          }
        }
    }else if (flag == TH_ACK){ 
          //1. find connfd socket
          //2. change state to ESTABLISHED
          //3. put in accepted_queue
          //4. return;
      for(std::set<socket*>::iterator it = connfd_set.begin(); it!=connfd_set.end(); ++it){
        socket* sock = *it;  
        if((sock->sockaddrinfo.src_port == destport) && (sock->sockaddrinfo.src_ipaddr == destip) 
        && (sock->sockaddrinfo.dest_port == srcport) && (sock->sockaddrinfo.dest_ipaddr == srcip)){
          if(sock->tcpinfo.tcpi_state == TCP_SYN_RECV){
            accepted_queue.push(sock);
            sock->tcpinfo.tcpi_state = TCP_ESTABLISHED;
            break;
          }
        }
      }
      return;
    }
  } 
 // TODO 3
  
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
    sock -> tcpinfo.tcpi_state = TCP_CLOSE;

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
  // delete this->pfdmap[pid]->fdmap[sockfd];
  // this->pfdmap[pid]->fdmap.erase(sockfd);
  // this->listenfd_map.erase(sock);
  // this-> clientfd_set.erase(sock);
  // this-> connfd_set.erase(sock);

  this->portmap.erase(this->pfdmap[pid]->fdmap[sockfd]->sockaddrinfo.src_port);
  delete(this->pfdmap[pid]->fdmap[sockfd]);
  this-> pfdmap[pid]->fdmap.erase(sockfd);
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
  size_t packet_size = 54, length = 20; // 54 is the minimum size of a packet
  Packet pkt (packet_size), temp_pkt (packet_size);
  uint8_t flag = TH_SYN, x2=0;
  uint16_t checksum_made, urp=0, wnd=51200; // checksum that will be sent
  uint32_t acknum = htonl(0), seqnum = htonl(0); // TODO: acknum 지정하는 게 맞아?
  uint8_t checksum_making[length] = {0,}; // used for checksum_made
  int ip_header = 26, tcp_header = 34;

  if(this->pfdmap.find(pid) == this->pfdmap.end()){ // nonexisting pid -> error
    returnSystemCall(syscallUUID, -1);
    return;
  }
  if(this->pfdmap[pid]->fdmap.find(fd) == this->pfdmap[pid]->fdmap.end()){ // nonexisting fd -> error
    returnSystemCall(syscallUUID, -1);
    return; // There must be 2 returns
  }

  sock = this->pfdmap[pid]->fdmap[fd];

  if(sock->tcpinfo.tcpi_state != TCP_CLOSE){ // The state of the socket must be LISTEN
    returnSystemCall(syscallUUID, -1);
    return;
  }

  // Given Destination Information
  memcpy(&(sock->sockaddrinfo.dest_port), addr->sa_data, 2);
  memcpy(&(sock->sockaddrinfo.dest_ipaddr), addr->sa_data+2, 4);

  // Dest IP for getRoutingTable
  memcpy(&dest_ip, addr->sa_data+2, 1);
  memcpy(&dest_ip+1, addr->sa_data+3, 1);
  memcpy(&dest_ip+2, addr->sa_data+4, 1);
  memcpy(&dest_ip+3, addr->sa_data+5, 1);

  // Select Src IP & Port
  sock -> sockaddrinfo.src_port = htons(1500+rand() % (30000)); // port num must be less than 65536
  int port = this -> getRoutingTable(dest_ip); // NIC port for getting src IP
  ipv4_t sourceip = this -> getIPAddr(port).value(); // src ip (using value() due to optional<ipv4_t>)
  sock -> sockaddrinfo.src_ipaddr = NetworkUtil::arrayToUINT64(sourceip);

  // fill src_addr
  struct sockaddr_in *newaddr = (struct sockaddr_in *) static_cast<struct sockaddr *>(sock->src_addr);
  newaddr -> sin_family = AF_INET;
  newaddr -> sin_addr.s_addr = sock->sockaddrinfo.src_ipaddr;
  newaddr -> sin_port = sock->sockaddrinfo.src_port;
  // cf) memcpy X, maybe due to htons... etc

  // Packet
  pkt.writeData(ip_header, &(sock->sockaddrinfo.src_ipaddr), 4);
  pkt.writeData(ip_header+4, &(sock->sockaddrinfo.dest_ipaddr), 4);
  std::cout<<"hi"<<std::endl;
  // make checksum
  temp_pkt.writeData(tcp_header, &(sock->sockaddrinfo.src_port), 2);
  temp_pkt.writeData(tcp_header+2, &(sock->sockaddrinfo.dest_port), 2);
  temp_pkt.writeData(tcp_header+4, &seqnum, 4);
  temp_pkt.writeData(tcp_header+8, &acknum, 4);
  temp_pkt.writeData(tcp_header+12, &x2, 1);
  temp_pkt.writeData(tcp_header+13, &flag, 1);
  temp_pkt.writeData(tcp_header+14, &wnd, 2);
  temp_pkt.writeData(tcp_header+18, &urp, 2);
  temp_pkt.readData(tcp_header, &checksum_making, 14);
  checksum_made = htons(~ NetworkUtil::tcp_sum(sock->sockaddrinfo.src_ipaddr,
                          sock->sockaddrinfo.dest_ipaddr, checksum_making, length));

  // Send Packet: SYN
  struct tcphdr tcphdr;
    tcphdr.th_sport = sock->sockaddrinfo.src_port;
    tcphdr.th_dport = sock->sockaddrinfo.dest_port;
    tcphdr.th_seq = seqnum;
    tcphdr.th_ack = acknum;
    tcphdr.th_flags = flag;
    tcphdr.th_sum = checksum_made;
    // TODO: th_off, th_x2, th_win, th_upr ??
    tcphdr.th_x2 = x2;
    tcphdr.th_off = 5;
    tcphdr.th_urp = urp;
    tcphdr.th_win = wnd;

  pkt.writeData(tcp_header, &tcphdr, 20);

  void *temp_buf = malloc(pkt.getSize());
  pkt.readData(0, temp_buf, pkt.getSize());


  this->sendPacket("IPv4", std::move(pkt));

  sock -> seqnum = seqnum; // Store seqnum
  sock -> tcpinfo.tcpi_state = TCP_SYN_SENT; // Change State
  sock -> SyscallUUID = syscallUUID; // Store UUID
  sock -> bind = 1; // BOUND
  this -> clientfd_set.insert(sock); // Insert to the clientfd set
  return;
}

void TCPAssignment::syscall_listen(UUID syscallUUID, int pid, int fd, int backlog){
// 1. make listenfd_map
// 2. change socket's state to LISTEN

  socket* listensock = this->pfdmap[pid]->fdmap[fd];
  pending_backlog* pending_backlog_struct = new pending_backlog;
  pending_backlog_struct -> backlog = backlog;
  listensock -> tcpinfo.tcpi_state = TCP_LISTEN;
  listenfd_map[listensock] = pending_backlog_struct;
  this -> returnSystemCall(syscallUUID, 0);
  
  //TODO: handling error
}

void TCPAssignment::syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen){
  //pid, fd -> listening socket.
  // make connfd & put client's address into struct sockaddr * addr
  //connfdmap에 넣어주기
  struct socket * listensock = this->pfdmap[pid]->fdmap[fd];
  struct sockaddrinfo listenaddrinfo = listensock->sockaddrinfo;
  std:: queue<struct sockaddrinfo *> pending_queue = this->listenfd_map[listensock]->pending_queue;
  if (!pending_queue.empty()){
    //find clientsocket
    //we have listensock src ipaddr/port. 
    //--> it is the same as client socket's dest ipaddr/port
    in_addr_t clientip = pending_queue.front()->src_ipaddr;
    in_port_t clientport = pending_queue.front()->src_port;

    //make connect socket
    struct socket * connsock  = new socket;
    int connfd = this -> createFileDescriptor(pid);
    PFDtable *pfd = this->pfdmap[pid];
    pfd->fdmap.insert({connfd, connsock});

    //add info to connsock
    connsock -> fd = connfd;
    connsock -> SyscallUUID = syscallUUID;
    connsock -> domain = listensock -> domain;
    connsock -> protocol = listensock -> protocol;
    connsock -> sockaddrinfo.src_port = listenaddrinfo.src_port;
    connsock -> sockaddrinfo.src_ipaddr = listenaddrinfo.src_ipaddr;
    connsock -> bind = 1; 
    connsock -> sin_family = AF_INET;
    connsock-> sockaddrinfo.dest_port = clientport;
    connsock-> sockaddrinfo.dest_ipaddr = clientip;
    connsock-> src_addr = listensock ->src_addr;
    connsock -> tcpinfo.tcpi_state = TCP_SYN_RECV;

    //save addr
    struct sockaddr_in *newaddr = (struct sockaddr_in *)static_cast<struct sockaddr *>(addr);
    newaddr -> sin_family = AF_INET;
    newaddr -> sin_addr.s_addr = clientip;
    newaddr -> sin_port = htons(clientport);
    
    pending_queue.pop();
    this->listenfd_map[listensock]->pending_queue = pending_queue;
    connfd_set.insert(connsock);
    this->returnSystemCall(syscallUUID, connsock->fd);
    return;
  }
  this->returnSystemCall(syscallUUID, -1);
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

  socket* sock;
  in_port_t peerport;
  in_addr_t peerip;

  if(this->pfdmap.find(pid) == this->pfdmap.end()){ // nonexisting pid
    returnSystemCall(syscallUUID, -1); // error
    return;
  }
  if(this->pfdmap[pid]->fdmap.find(fd) == this->pfdmap[pid]->fdmap.end()){ // nonexisting fd
    returnSystemCall(syscallUUID, -1); // error
    return;
  }

  sock = this->pfdmap[pid]->fdmap[fd];
  addr->sa_family = AF_INET;

  if((this->clientfd_set.find(sock) != this->clientfd_set.end()) // fd is clientfd
      || (this->connfd_set.find(sock) != this->connfd_set.end())){ // fd is connfd

      peerport = sock -> sockaddrinfo.dest_port;
      peerip = sock -> sockaddrinfo.dest_ipaddr;

      memcpy(addr->sa_data, &peerport, 2);
      memcpy(addr->sa_data+2, &peerip, 4);
      
      addrlen = (socklen_t *)sizeof(* addr);

      returnSystemCall(syscallUUID, 0);
      return;
    }

  returnSystemCall(syscallUUID, -1); // error
  return;
  
}

} // namespace E