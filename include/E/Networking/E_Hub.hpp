/*
 * E_Hub.hpp
 *
 *  Created on: 2014. 11. 10.
 *      Author: Keunhong Lee
 */

#ifndef E_HUB_HPP_
#define E_HUB_HPP_

#include <E/Networking/E_Link.hpp>

namespace E {

class Hub : public Link {
protected:
  virtual void packetArrived(const ModuleID inWireID, Packet &&packet);

public:
  Hub(std::string name, NetworkSystem &system);
};

} // namespace E

#endif /* E_HUB_HPP_ */
