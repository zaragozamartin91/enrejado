block_ports = set() 
from pox.core import core 

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
  
def launch (forwarding = "l2"):
  import pox.log.color
  pox.log.color.launch()
  import pox.log
  pox.log.launch(format="[@@@bold@@@level%(name)-22s@@@reset] " + "@@@bold%(message)s@@@normal")
  from pox.core import core
  import pox.openflow.discovery
  pox.openflow.discovery.launch()

  core.getLogger("openflow.spanning_tree").setLevel("INFO")
  if forwarding.lower() == "l3":
    import pox.forwarding.l3_learning as fw
  elif forwarding.lower() == "l2_multi":
    import pox.forwarding.l2_multi as fw
  else:
    import pox.forwarding.l2_learning as fw
  core.getLogger().debug("Using forwarding: %s", fw.__name__)
  fw.launch()

  import pox.openflow.spanning_tree
  pox.openflow.spanning_tree.launch()