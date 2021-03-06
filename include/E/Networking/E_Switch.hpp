/*
 * E_Switch.hpp
 *
 *  Created on: Mar 14, 2015
 *      Author: leeopop
 */

#ifndef E_SWITCH_HPP_
#define E_SWITCH_HPP_

#include <E/Networking/E_Link.hpp>

namespace E {

class Switch : public Link {
private:
  std::unordered_map<ModuleID, std::unordered_set<uint64_t>> mac_table;
  E::UniformDistribution dist;
  bool unreliable;
  Real drop_base;
  Real drop_base_diff;
  Real drop_base_limit;
  Real drop_base_final;

protected:
  virtual void packetArrived(const ModuleID inWireID, Packet &&packet);

public:
  Switch(std::string name, NetworkSystem &system, bool unreliable = false);
  void addMACEntry(int port, const mac_t &mac);
};

} // namespace E

#endif /* E_SWITCH_HPP_ */
