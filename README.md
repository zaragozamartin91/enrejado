# enrejado :: Proyecto con p0x y m1n1n37

## Prueba de topologia

* Abrir una terminal e iniciar controlador pox mediante: `pox/pox.py samples.zgn-spanning_tree`.
* Abrir __otra__ terminal y levantar la topologia mediante: `sudo mn --custom mininet/custom/zgn-fattree.py --topo fattree --mac --arp --switch ovsk --controller remote`. Sobre esta terminal aparecera un prompt de mininet `mininet>`.
* Sobre el prompt de mininet correr: `pingall` (_Puede demorar hasta 10min en finalizar_).
* Cuando pingall haya terminado de correr , entonces todos los hosts conoceran a todos los demas dispositivos.

## Consulta de informacion de controlador

### web.webcore y openflow.webservice

Los modulos __web.webcore__ y __openflow.webservice__ sirven para exponer una interfaz web en el puerto 8000 que permite consultar informacion sobre los componentes de pox.

Ejemplo:
Corriendo
`pox/pox.py log.level --DEBUG --packet=WARN samples.pretty_log web.webcore openflow.webservice forwarding.l2_pairs`

Luego podemos consultar la informacion de los switches mediante:
`curl -i -X POST -d '{"method":"get_switches","id":1}' http://127.0.0.1:8000/OF/`

De esta manera, se obtiene informacion de los switches como JSON:
`{"result": [{"n_tables": 254, "ports": [{"hw_addr": "9a:28:f8:82:07:ca", "name": "s1-eth1", "port_no": 1}, ..., {"hw_addr": "0a:8e:91:77:80:79", "name": "s3-eth2", "port_no": 2}, {"hw_addr": "be:19:74:f8:ee:48", "name": "s3", "port_no": 65534}], "dpid": "00-00-00-00-00-03"}], "id": 1}`

### Modulo PY

Es posible iniciar un controlador de POX junto con un CLI que permite hacer consultas sobre dicho controlador. 

Del lado del controlador se pueden exponer variables y datos al CLI mediante el modulo __core.Interactive__.

Por ejemplo, si quisieramos exponer un diccionario con todos los Switches del controlador podemos escribir:
`core.Interactive.variables['switches'] = switches` y luego del lado del CLI solicitar y afectar dicha variable haciendo referencia a su nombre __switches__.

Para iniciar un controlador junto con el CLI, correr el modulo __py__ en la terminal junto con el resto de los modulos del controlador POX que deseamos correr: `./pox/pox.py misc.zgn_lswitch_fattree log.level --DEBUG --packet=WARN web.webcore openflow.webservice py`
