#! /usr/bin/env python
#For Python, this file uses encoding: utf-8

import sys
import numpy as np
import math as mat
from tabulate import tabulate

def esBroadcast(packet):
	return packet.dst == "ff:ff:ff:ff:ff:ff"

def entropia( probaPorSimbolo ):
	res = 0
	for s,p in probaPorSimbolo.items():
		res -= p * mat.log( p, 2)
	return res	 

def informacionPorSimbolo(probaPorSimbolo):
	res = {}
	for simbolo,probabilidad in probaPorSimbolo.items():
		informacion = (-1) * mat.log( probabilidad, 2)
		res[simbolo] = informacion
	return res

from scapy.all import *

def main(archivo,modeloAUtilizar):
	print "Leyendo archivo..."
	pcapFile = rdpcap( archivo )
	totalDePaquetes = len(pcapFile)
	broadcastCount = 0
	unicastCount = 0
	protocolos = set()
	simbolosPosibles = set()
	contadorDeSimbolos = {}
	 
	broadcast = "BROADCAST"
	unicast = "UNICAST"

	print "Analizando la fuente..."

	if (modeloAUtilizar == 0):

		for packet in pcapFile:

			primerComponente = ""
			protocolo = packet.payload.name

			if esBroadcast(packet):
				broadcastCount += 1
				primerComponente = broadcast
			else:
				unicastCount += 1
				primerComponente = unicast

			protocolos.add(protocolo) 
			simbolosPosibles.add( (broadcast, protocolo) )
			simbolosPosibles.add( (unicast, protocolo) )

			simbolo = (primerComponente, protocolo)
			
			if simbolo in contadorDeSimbolos:
				contadorDeSimbolos[simbolo] += 1
			else:
				contadorDeSimbolos[simbolo] = 1
	elif (modeloAUtilizar == 1): 
		
		#TODO modelo que distingue por ARP.dst, creo que es solo filtrar los ARP y hacer: packet.payload.dst
		pass
	else:
		print "Uso incorrecto, el segundo parametro deber ser 0 o 1."
		print "Uso: python script.py pcapFile modeloAUtilizar(0/1)\nDonde modeloAUtilizar es 0 si no se distinguen los host y 1 en caso contrario. "
		sys.exit()

	probaPorSimbolo = dict((key, float(value)/totalDePaquetes) for (key,value) in contadorDeSimbolos.items())
	informacionXSimbolo = informacionPorSimbolo(probaPorSimbolo)
	entropiaMuestral = entropia(probaPorSimbolo)
	entropiaMaxima = mat.log (len(contadorDeSimbolos),2)
	
	#No sé si los que tienen proba 0 tendrán que figurar o no... Decidamos (?)

	return (probaPorSimbolo,informacionXSimbolo,totalDePaquetes,broadcastCount,protocolos)

def armarTabla(probabilidades,informaciones,cantidadDePaquetes,cantidadBroadcast,protocolos):
	#Impresiones

	entropiaMuestral = entropia(probabilidades)
	entropiaMaxima = mat.log(len(probabilidades),2)
	print "Size de la muestra: " + str(cantidadDePaquetes)

	print "Entropia muestral: "
	print "\t\t",entropiaMuestral
	print "Entropia Maxima: "
	
	print "\t\t",entropiaMaxima
	
	tabla = []
	for s,p in probabilidades.items(): 
		tabla.append([s,p,informaciones[s]])
	
	print(tabulate(tabla, headers=['Simbolo', 'Probabilidad', 'Informacion']))

if __name__ == '__main__':
	if len(sys.argv) != 3 :
		print "Uso: python script.py pcapFile modeloAUtilizar(0/1)\nDonde modeloAUtilizar es 0 si no se distinguen los host y 1 en caso contrario. "
		sys.exit()
	else:
		armarTabla(*main(sys.argv[1],int(sys.argv[2])))
