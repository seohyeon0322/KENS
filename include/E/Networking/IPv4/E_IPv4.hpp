/*
 * E_IPv4.hpp
 *
 *  Created on: 2014. 11. 20.
 *      Author: Keunhong Lee
 */

#ifndef E_IPV4_HPP_
#define E_IPV4_HPP_

#include <E/Networking/E_Host.hpp>
#include <E/Networking/E_Networking.hpp>

namespace E {

class IPv4 : public HostModule {
private:
  uint16_t identification;

public:
  IPv4(Host &host);
  virtual ~IPv4();

protected:
  virtual void packetArrived(std::string fromModule, Packet &&packet) final;
};

} // namespace E

#endif /* E_IPV4_HPP_ */
