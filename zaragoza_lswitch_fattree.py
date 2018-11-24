from pox.core import core 
import pox.log.color
import pox.log
import pox.openflow.discovery
import pox.openflow.spanning_tree
from pox.lib.recoco import Timer
from collections import defaultdict
import pox.openflow.libopenflow_01 as of
import pox.lib.packet as pkt
import time
from pox.lib.util import dpid_to_str

block_ports = set() 
log = core.getLogger()

# diccionario de componentes adyacentes
# The defaultdict will simply create any non-existing items that you try to access. To create such a "default" item, it calls the function object that you pass in the constructor 
adj = defaultdict(lambda:defaultdict(lambda:[]))
# set de switch_ids
switch_ids = set()
# diccionario switch_id -> Switch (ver clase mas abajo)
switches = dict()

# Determinan / ajustan un tiempo de bloqueo de floods. 
# Este tiempo se incrementara cada vez que se detecte un nuevo switch y un nuevo enlace
FLOOD_DELAY_INCREMENT = 1
_flood_delay = FLOOD_DELAY_INCREMENT

DHCP_PORT = 67


def find_switch_path(curr_switch_id , end_switch_id , found_paths = [], curr_path = []):
  print('curr_switch_id: ' , curr_switch_id , ' ; end_switch_id: ' , end_switch_id , ' ; curr_path: ' , curr_path)
  path_copy = list(curr_path) # copio la lista del path actual
  path_copy.append(curr_switch_id) # agrego el switch actual a la lista
  # si el switch actual es igual al que busco -> encontre un camino valido
  if curr_switch_id == end_switch_id: 
    found_paths.append(path_copy)
    print('Path found: ' , path_copy)
    return True
  any_path_found = False
  for adj_sw_id in adj[curr_switch_id]:
    # evito visitar nuevamente los mismos switches
    if adj_sw_id not in curr_path:
      path_found = find_switch_path(adj_sw_id , end_switch_id , found_paths , path_copy)
      any_path_found = any_path_found or path_found
  return any_path_found

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
    global _flood_delay
    _flood_delay = _flood_delay + FLOOD_DELAY_INCREMENT
    log.debug('NUEVO SWITCH DETECTADO _flood_delay: %d SEGUNDOS' % _flood_delay)
    # Creo un nuevo switch
    Switch(event.connection , event.dpid)
    
  def _handle_LinkEvent (self, event):
    """ Listener de NUEVO ENLACE """
    global _flood_delay
    _flood_delay = _flood_delay + FLOOD_DELAY_INCREMENT
    log.debug('NUEVO ENLACE DETECTADO _flood_delay: %d SEGUNDOS' % _flood_delay)
    self._adjust_adjacency()
    
  def _adjust_adjacency(self):
    """ Ajusta la ADYACENCIA entre componentes conectados """
    log.debug('AJUSTANDO ADYACENCIA')
    adj.clear()
    switch_ids.clear()
    # por cada enlace nuevo, se ajustan adj y switch_ids
    for l in core.openflow_discovery.adjacency:
      adj[l.dpid1][l.dpid2].append(l)
      switch_ids.add(l.dpid1)
      switch_ids.add(l.dpid2)

# Switch CLASS ----------------------------------------------------------------------------------------

class Switch:
  def __init__ (self , connection , dpid):
    # Guarda la conexion con el switch
    self.connection = connection
    # guardo el id del switch y un sinonimo del mismo
    self.switch_id = dpid
    self.dpid = dpid
    log.info("SWITCH %s CONECTADO" % self.switch_id)
    # TABLA Mac -> puerto_salida_switch
    self.mac_to_port = {}
    # Agrego listeners de conexion (como PacketIn)
    self.connection.addListeners(self)
    switches[dpid] = self
    
    
  def _handle_PacketIn (self, event):
    packet_in = event.ofp # objeto EVENTO de tipo PACKET_IN.
    packet = event.parsed
    
    src_mac = packet.src # MAC origen del paquete
    dst_mac = packet.dst # MAC destino del paquete
    in_port = packet_in.in_port # puerto de switch por donde ingreso el paquete
    
    def install_flow(out_port):
      """ Instala un flujo en el switch del tipo MAC_ORIGEN@PUERTO_ENTRADA -> MAC_DESTINO@PUERTO_SALIDA """
      log.debug("installing flow for %s.%i -> %s.%i" % (src_mac, in_port, dst_mac, out_port))
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match.from_packet(packet, in_port)
      msg.idle_timeout = 10
      msg.hard_timeout = 30
      msg.actions.append(of.ofp_action_output(port = out_port))
      msg.data = packet_in
      self.connection.send(msg)
      
    def drop (duration = None):
      """
      Dropea el paquete y opcionalmente instala un flujo en el switch para que siga dropeando paquetes de este tipo.
      NOTA: PODRIA USARSE PARA EL FIREWALL
      """
      if duration is not None:
        if not isinstance(duration, tuple): duration = (duration,duration)
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match.from_packet(packet)
        msg.idle_timeout = duration[0]
        msg.hard_timeout = duration[1]
        msg.buffer_id = packet_in.buffer_id
        self.connection.send(msg)
      elif packet_in.buffer_id is not None:
        msg = of.ofp_packet_out()
        msg.buffer_id = packet_in.buffer_id
        msg.in_port = in_port
        self.connection.send(msg)
        
    def flood ():
      """ Hace un flood de los paquetes UNICAMENTE por los puertos habilitados por SPT """
      msg = of.ofp_packet_out() # se crea el mensaje de flood
      time_diff = time.time() - self.connection.connect_time
      flood_ok = time_diff >= _flood_delay
      if flood_ok:
        # Realizar flood solo despues de que venza el tiempo de prevencion de flood
        log.debug("SWITCH_%i: FLOOD %s -> %s", self.switch_id,src_mac,dst_mac)
        # output all openflow ports except the input port and those with flooding disabled via the OFPPC_NO_FLOOD port config bit (generally, this is done for STP)
        msg.actions.append(of.ofp_action_output(port = of.OFPP_FLOOD))
      else:
        log.info("ESPERANDO FLOOD DE SWITCH %s , RESTAN %d SEGUNDOS" % (self.switch_id, int(_flood_delay - time_diff)))
      msg.data = packet_in
      msg.in_port = in_port
      self.connection.send(msg)

    def handle_all():
      """ Maneja los paquetes de forma generica """
      # TODO : MODIFICAR ESTE COMPORTAMIENTO PARA SOPORTAR ECMP
      # si el puerto de salida se encuentra en la tabla de MACs entonces instalo un flujo en el switch
      if dst_mac in self.mac_to_port:
        out_port = self.mac_to_port[dst_mac]
        install_flow(out_port)
      else:
        flood()
    
    eth_getNameForType = pkt.ETHERNET.ethernet.getNameForType(packet.type)
    # Parseo tempranamente los tipos de datos conocidos 
    pkt_is_ipv6 = eth_getNameForType == 'IPV6'
    icmp_pkt = packet.find('icmp')
    tcp_pkt = packet.find('tcp')
    udp_pkt = packet.find('udp')
    pkt_is_arp = packet.type == packet.ARP_TYPE
    ip_pkt = packet.find('ipv4')
    
    def handle_dhcp():
      """ Maneja paquetes DHCP ... Pensar si acaso deberian dropearse... """
      dstip = ip_pkt.dstip
      log.info('MANEJANDO PAQUETE DHCP HACIA IP %s' % str(dstip) )
      handle_all()
    
    def handle_udp():
      """ Maneja paquetes UDP. Debe detectar ataques udp e instalar un firewall temporal en el switch """
      dstip = ip_pkt.dstip
      dstport = udp_pkt.dstport
      if dstport == DHCP_PORT : return handle_dhcp()
      log.info('MANEJANDO PAQUETE UDP HACIA IP %s:%d' % (str(dstip),dstport) )
      handle_all()
      
    
    # LOS PAQUETES DESCONOCIDOS SON DROPEADOS. POR AHORA IGNORAMOS LOS PAQUETES IPV6
    unknown_pkt = pkt_is_ipv6 or ( icmp_pkt is None and tcp_pkt is None and udp_pkt is None and not pkt_is_arp )
    if unknown_pkt:
      #log.info('PAQUETE DESCONOCIDO DETECTADO')
      drop()
      return
    
    # Obtengo el nombre 'imprimible' del paquete
    pkt_type_name = ''
    if icmp_pkt : pkt_type_name = 'ICMP'
    if tcp_pkt : pkt_type_name = 'TCP'
    if udp_pkt : pkt_type_name = 'UDP'
    if pkt_is_arp : pkt_type_name = 'ARP'
    log.info('SWITCH_%s#PORT_%d -> PAQUETE TIPO %s::%s MAC_ORIGEN: %s MAC_DESTINO: %s' % 
      (self.switch_id,in_port,eth_getNameForType,pkt_type_name,src_mac,dst_mac))
    
    # guardo la asociacion mac_origen -> puerto_entrada
    self.mac_to_port[src_mac] = in_port
    
    # si el paquete es udp lo manejo como tal
    if udp_pkt and ip_pkt: return handle_udp()
 
    handle_all() 
      
    
# launch ----------------------------------------------------------------------------------------------------------------------


def launch ():
  pox.log.color.launch()
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " + "@@@bold%(message)s@@@normal")  
  
  pox.openflow.discovery.launch()
  
  # no_flood: If True, we set ports down when a switch connects
  # hold_down: If True, don't allow turning off flood bits until a complete discovery cycle should have completed (mostly makes sense with _noflood_by_default).
  pox.openflow.spanning_tree.launch(no_flood = True, hold_down = True)
  
  
  core.registerNew(ZgnLswitchFattree)
  
  # Estas lineas de abajo exponen las variables adj y switch_ids al modulo interactivo de pox 'PY'
  core.Interactive.variables['adj'] = adj
  core.Interactive.variables['switch_ids'] = switch_ids
  core.Interactive.variables['switches'] = switches
  
  # AVERIGUAR PARA QUE SIRVE WaitingPath EN l2_multi
  #timeout = min(max(PATH_SETUP_TIME, 5) * 2, 15)
  #Timer(timeout, WaitingPath.expire_waiting_paths, recurring=True)


  
pox.openflow.spanning_tree.launch()