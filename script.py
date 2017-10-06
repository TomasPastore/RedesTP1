#! /usr/bin/env python
#For Python, this file uses encoding: utf-8

import sys
import numpy as np
import math as mat
from tabulate import tabulate

def esBroadcast(packet):
	return packet.dst == "ff:ff:ff:ff:ff:ff"

def pertenece(string, list):
	for s in list:
		if s == string:
			return True

	return False

#¿Realmente hace falta usar esto? .-.
def hacerTupla(first, second):
	return (first,second)

#Precondicion: simbolo pertenece a simbolos
def indiceDeSimbolo(simbolo, simbolos):
	for i in range(0,len(simbolos)) :
		if simbolo == simbolos[i]:
			return i

#entran < proba, simbolo >
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
	#horrible pero bue, 50 tienen que alcanzar
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
	else: 
		pass	
		#TODO modelo que distingue por ARP.dst, creo que es solo filtrar los ARP y hacer: packet.payload.dst

	probaPorSimbolo = dict((key, float(value)/totalDePaquetes) for (key,value) in contadorDeSimbolos.items())

	#No sé si los que tienen proba 0 tendrán que figurar o no... Decidamos (?)
	
	#Impresiones
	print "Size de la muestra: " + str(totalDePaquetes)

	informacionXSimbolo = informacionPorSimbolo(probaPorSimbolo)

	entropiaMuestral = entropia(probaPorSimbolo)	
	
	print "Entropia muestral: "
	print "\t\t",entropiaMuestral
	print "Entropia Maxima: "
	entropiaMaxima = mat.log (len(contadorDeSimbolos),2)

	# for i in range(0, len(informacionXSimbolo)): 
	# 	if informacionXSimbolo[i][1] > entropiaMaxima:
	# 		entropiaMaxima = informacionXSimbolo[i][1]
	
	print "\t\t",entropiaMaxima
	# Imprime tabla a partir de los datos de 
	# una lista de listas:
	tabla = []
	for s,p in probaPorSimbolo.items(): 
		tabla.append([s,p,informacionXSimbolo[s]])
	
	print(tabulate(tabla, headers=['Simbolo', 'Probabilidad', 'Informacion']))

if __name__ == '__main__':
	if len(sys.argv) != 3 :
		print "Uso: python script.py pcapFile modeloAUtilizar(0/1)\n Donde modeloAUtilizar es 0 si no se distinguen los host y 1 en caso contrario. "
		sys.exit()
	else:
		main(sys.argv[1],int(sys.argv[2]))
