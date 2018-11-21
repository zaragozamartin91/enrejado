# enrejado :: Proyecto con p0x y m1n1n37

## Prueba de topologia

* Abrir una terminal e iniciar controlador pox mediante: `pox/pox.py samples.zgn-spanning_tree`.
* Abrir __otra__ terminal y levantar la topologia mediante: `sudo mn --custom mininet/custom/zgn-fattree.py --topo fattree --mac --arp --switch ovsk --controller remote`. Sobre esta terminal aparecera un prompt de mininet `mininet>`.
* Sobre el prompt de mininet correr: `pingall` (_Puede demorar hasta 10min en finalizar_).
* Cuando pingall haya terminado de correr , entonces todos los hosts conoceran a todos los demas dispositivos.

## Consulta de informacion de controlador

Los modulos __web.webcore__ y __openflow.webservice__ sirven para exponer una interfaz web en el puerto 8000 que permite consultar informacion sobre los componentes de pox.

Ejemplo:
Corriendo
_pox/pox.py log.level --DEBUG --packet=WARN samples.pretty_log web.webcore openflow.webservice forwarding.l2_pairs_

Luego podemos consultar la informacion de los switches mediante:
_curl -i -X POST -d '{"method":"get_switches","id":1}' http://127.0.0.1:8000/OF/_

De esta manera, se obtiene informacion de los switches como JSON:
`{"result": [{"n_tables": 254, "ports": [{"hw_addr": "9a:28:f8:82:07:ca", "name": "s1-eth1", "port_no": 1}, ..., {"hw_addr": "0a:8e:91:77:80:79", "name": "s3-eth2", "port_no": 2}, {"hw_addr": "be:19:74:f8:ee:48", "name": "s3", "port_no": 65534}], "dpid": "00-00-00-00-00-03"}], "id": 1}`
