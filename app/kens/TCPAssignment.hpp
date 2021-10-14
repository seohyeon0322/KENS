/*
 * E_TCPAssignment.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_TCPASSIGNMENT_HPP_
#define E_TCPASSIGNMENT_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>
#include <E/Networking/E_TimerModule.hpp>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#include <unordered_map>
#include <queue>
#include <bitset>


namespace E {

class TCPAssignment : public HostModule,
                      private RoutingInfoInterface,
                      public SystemCallInterface,
                      public TimerModule {
private:
  virtual void timerCallback(std::any payload) final;

public:
  TCPAssignment(Host &host);
  virtual void initialize();
  virtual void finalize();
  virtual ~TCPAssignment();
  // add
  virtual void syscall_socket(UUID syscallUUID, int pid, int domain, int type, int protocol);
  virtual void syscall_close(UUID syscallUUID, int pid, int sockfd);
  virtual void syscall_read(UUID syscallUUID, int pid, int fd, void *buf, int count);
  virtual void syscall_write(UUID syscallUUID, int pid, int fd, void *buf, int count);
  virtual void syscall_connect(UUID syscallUUID, int pid, int fd, struct sockaddr* addr, socklen_t addrlen);
  virtual void syscall_listen(UUID syscallUUID, int pid, int fd, int backlog);
  virtual void syscall_accept(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen);
  virtual void syscall_bind(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t addrlen);
  virtual void syscall_getsockname(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen);
  virtual void syscall_getpeername(UUID syscallUUID, int pid, int fd, struct sockaddr *addr, socklen_t *addrlen);

  struct sockaddrinfo{
        in_port_t src_port = 0;
        in_addr_t src_ipaddr = 0;
        in_port_t dest_port = 0;
        in_addr_t dest_ipaddr = 0;
    };
    
  struct socket{ // 1) socket information
        int fd;
        UUID SyscallUUID = 0;
        int domain = 0;
        int protocol = 0;
        sa_family_t sin_family;
        struct sockaddrinfo sockaddrinfo;
        sockaddr* src_addr = NULL;
        int bind = 0;
        int state = TCP_CLOSE;
        struct tcp_info tcpinfo;
        uint32_t seqnum;
    };

  struct PFDtable{ // 2) pid, fd->socket, (port, ip)
      int pid;
      std :: unordered_map<int, struct socket *> fdmap;
      std:: set<std:: pair<in_port_t, in_addr_t>> portippair;
    };

  struct pending_backlog{ //for saving backlog, pendingqueue. (We have pendingqueue per listenfd.)
    int backlog;
    std:: queue<struct sockaddrinfo *> pending_queue;
  };
    std:: unordered_map<socket*, pending_backlog*> listenfd_map; // map socket(listen_socket) with pending_queue(with backlog)

  //pending_backlog & listenfd
  // 1. make listenfd_map in listen()
  // 2. in packet_arrived(), using packet's destip/port, find listening socket.
  // 3. put clientsocket in pending_queue. (find socket in clientfd_set.)
  // 4. change clientsocket's state.

    //this is for saving clientsocket -> in accept(socket, &addr, len) we have to put address information to &addr. 
    //1. find clientsocket in pendingqueue. we can use pop() 
    //2. socket structure have sockaddrinfo -> find src ip/port, dest ip/port -> put in &addr



      std:: unordered_map<int, struct PFDtable *> pfdmap; // 3) pid -> PFDtable


      std:: unordered_map<in_port_t, int> portmap; // 4) port to pid


      std:: queue<struct socket *> accepted_queue; // 7) socket queue(accepted)

      std:: set<socket *> clientfd_set;
      std:: set<socket *> connfd_set;

      // std:: unordered_map<std::tuple<in_port_t,in_addr_t,in_port_t,in_addr_t>, struct socket *> clientfd_map; // 8) key: (srcport, srcip, destport, destip)
      // std:: unordered_map<std::tuple<in_port_t,in_addr_t,in_port_t,in_addr_t>, struct socket *> connfd_map; // 9) 




protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

};

class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */