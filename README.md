# enrejado :: Proyecto con p0x y m1n1n37

## Prueba de topologia

* Abrir una terminal e iniciar controlador pox mediante: `pox/pox.py samples.spanning_tree`.
* Abrir __otra__ terminal y levantar la topologia mediante: `sudo mn --custom mininet/custom/zgn-fattree.py --topo fattree --mac --arp --switch ovsk --controller remote`. Sobre esta terminal aparecera un prompt de mininet `mininet>`.
* Sobre el prompt de mininet correr: `pingall` (_Puede demorar hasta 10min en finalizar_).
* Cuando pingall haya terminado de correr , entonces todos los hosts conoceran a todos los demas dispositivos.
