from pox.core import core 
import pox.log.color
import pox.log
import pox.openflow.discovery
import pox.openflow.spanning_tree
from pox.lib.recoco import Timer
from collections import defaultdict

block_ports = set() 
log = core.getLogger()

# diccionario de componentes adyacentes
adj = defaultdict(lambda:defaultdict(lambda:[]))
# set de switches
switches = set()

# CONTROLLER FIREWALL ------------------------------------------------------------------------------------
def block_handler (event):   
  # Handles packet events and kills the ones with a blocked port number 
  tcpp = event.parsed.find('tcp')   
  if not tcpp: return # Not TCP   
  if tcpp.srcport in block_ports or tcpp.dstport in block_ports:     
  # Halt the event, stopping l2_learning from seeing it     
  # (and installing a table entry for it)     
    core.getLogger("blocker").debug("Blocked TCP %s <-> %s", tcpp.srcport, tcpp.dstport) 
    event.halt = True 
 
def unblock (*ports):   
  block_ports.difference_update(ports) 
 
def block (*ports): 
  block_ports.update(ports)

  
# CONTROLLER CLASS ----------------------------------------------------------------------------------------
  
class ZgnLswitchFattree:
  def __init__ (self):
    # Listen to dependencies
    def startup ():
      core.openflow.addListeners(self, priority=0)
      core.openflow_discovery.addListeners(self)
      log.debug("ZgnLswitchFattree ESTA LISTO")
      
    core.call_when_ready(startup, ('openflow','openflow_discovery'))

  def _handle_ConnectionUp (self, event):
    """ Listener de NUEVO SWITCH conectado """
    # Creo un nuevo switch
    Switch(event.connection , event.dpid)
    
  def _handle_LinkEvent (self, event):
    """ Listener de NUEVO ENLACE """
    log.debug('NUEVO ENLACE DETECTADO')
    self._adjust_adjacency()
    
  def _adjust_adjacency(self):
    """ Ajusta la ADYACENCIA entre componentes conectados """
    log.debug('AJUSTANDO ADYACENCIA')
    _adj = defaultdict(lambda:defaultdict(lambda:[]))
    _switches = set()
    # por cada enlace nuevo, se ajustan adj y switches
    for l in core.openflow_discovery.adjacency:
      _adj[l.dpid1][l.dpid2].append(l)
      _switches.add(l.dpid1)
      _switches.add(l.dpid2)
    adj = _adj
    switches = _switches

class Switch:
  def __init__ (self , connection , dpid):
    # Guarda la conexion con el switch
    self.connection = connection
    self.switch_id = dpid
    log.info("SWITCH %s CONECTADO" % self.switch_id)
    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}
    # This binds our PacketIn event listener
    self.connection.addListeners(self)
    
  def _handle_PacketIn (self, event):
    packet_in = event.ofp # objeto EVENTO de tipo PACKET_IN.
    packet = event.parsed
    
    pkt_type_name = str(packet.type)
    if packet.type == packet.LLDP_TYPE : pkt_type_name = 'LLDP'
    if packet.type == packet.ARP_TYPE : pkt_type_name = 'ARP'
    if packet.type == packet.IP_TYPE : pkt_type_name = 'IP'
    
    src_mac = packet.src # MAC origen del paquete
    dst_mac = packet.dst # MAC destino del paquete
    in_port = packet_in.in_port # puerto de switch por donde ingreso el paquete
    
    log.info('SWITCH_%s#PORT_%d -> PAQUETE TIPO %s MAC_ORIGEN: %s MAC_DESTINO: %s' % (self.switch_id,in_port,pkt_type_name,src_mac,dst_mac))
    if packet.type == packet.LLDP_TYPE or packet.dst.isBridgeFiltered():
      log.info('PAQUETE LLDP DETECTADO EN ZgnLswitchFattree')
      drop() # 2a
      return
      
      
    
# END OF CONTROLLER SWITCH --------------------------------------------------------------------------------
def launch ():
  pox.log.color.launch()
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " + "@@@bold%(message)s@@@normal")  
  
  pox.openflow.discovery.launch()
  
  # no_flood: If True, we set ports down when a switch connects
  # hold_down: If True, don't allow turning off flood bits until a complete discovery cycle should have completed (mostly makes sense with _noflood_by_default).
  pox.openflow.spanning_tree.launch(no_flood = True, hold_down = True)
  
  
  core.registerNew(ZgnLswitchFattree)
  # AVERIGUAR PARA QUE SIRVE WaitingPath EN l2_multi
  #timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  #Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)


  
pox.openflow.spanning_tree.launch()