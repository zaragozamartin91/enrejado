#!/usr/bin/python

# fat-tree configurable con valor de altura
# uso: mn --custom <ruta a mz-fattree.py> --topo fattree,<altura_arbol>,<cantidad_clientes>

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.cli import CLI


class ZgnFatTree(Topo):
	""" Topologia fat-tree simple """

	def __init__(self, tree_height = 3 , lhost_count = 2 , chost_count = 3 , **opts):
		Topo.__init__(self , **opts)
		# creo los switches
		leaf_sws = self.build_switches(0, tree_height)
		# creo los hosts raiz
		total_lhosts = self.build_lhosts(leaf_sws , lhost_count)
		# creo los hosts cliente conectados al switch raiz
		for i in range(chost_count):
			host_id = total_lhosts + i + 1
			chost = self.addHost('h%s' % host_id)
			self.addLink(self.root_sw, chost)
	
	
	def build_switches(self , level, last_level , parent_sws = [] , total_sw_count = 0):
		""" Crea la red de switches """
		if level == last_level : return parent_sws
		sws = []
		# cantidad de switches en este nivel
		sw_count = 2**level
		lower_bound = total_sw_count
		upper_bound = lower_bound + sw_count
		for i in range(lower_bound , upper_bound):
			sw_id = i
			# creo un switch
			sw = self.addSwitch('s%s' % sw_id)
			if level == 0 : self.root_sw = sw
			sws.append(sw)
			# conecto el nuevo switch con todos los switches padre
			for parent_sw in parent_sws:
				self.addLink(sw, parent_sw)
		# los switches creados en este nivel seran los padres del nivel siguiente
		return self.build_switches(level + 1 , last_level , sws , total_sw_count + sw_count)
		
		
	def build_lhosts(self , sws , lhost_count):
		""" Crea los hosts hojas """
		host_count = 0
		for sw in sws:
			for i in range(lhost_count):
				host_id = host_count + 1
				host = self.addHost('h%s' % host_id)
				self.addLink(sw, host)
				host_count += 1
		return host_count
		
	
		
topos = { 'fattree': ZgnFatTree }

