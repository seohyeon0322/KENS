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
#include <tuple>

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
  virtual int packetflag(uint8_t flag);

protected:
  virtual void systemCallback(UUID syscallUUID, int pid,
                              const SystemCallParameter &param) final;
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;

struct socket{ // 1) socket information
      UUID SyscallUUID;
      int domain;
      int protocol;
      sa_family_t sin_family;
      uint16_t src_port;
      uint32_t src_ipaddr;
      uint16_t dest_port;
      uint32_t dest_ipaddr;
      sockaddr* src_addr;
      int bind = 0;
      int state = 0;
      //TODO: state = 0 for debugging;
  };

 struct PFDtable{ // 2) pid, fd->socket, (port, ip)
    int pid;
    std :: unordered_map<int, socket *> fdmap;
    std:: set<std:: pair<uint16_t, uint32_t>> portippair;
  };

  std:: unordered_map<int, PFDtable *> pfdmap; // 3) pid -> PFDtable

  std:: unordered_map<uint16_t, int> portmap; // 4) port to pid

  typedef std::tuple <uint16_t,uint32_t,uint16_t,uint32_t> sockaddrinfo; // 5) (srcport, srcip, destport, destip)

  std:: queue<sockaddrinfo> pending_queue; // 6) socket queue

  std:: queue<struct socket> accepted_queue; // 7) socket queue(accepted)
  
  std:: unordered_map<sockaddrinfo, struct socket> clientfd_map; // 8) key: (srcport, srcip, destport, destip)
  std:: unordered_map<sockaddrinfo, struct socket> connfd_map; // 9) 
};

//TODO: struct로 할지 class로 할지 고민해보기;
//socket datastructure;
class TCPAssignmentProvider {
private:
  TCPAssignmentProvider() {}
  ~TCPAssignmentProvider() {}

public:
  static void allocate(Host &host) { host.addHostModule<TCPAssignment>(host); }
};

} // namespace E

#endif /* E_TCPASSIGNMENT_HPP_ */