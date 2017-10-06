#! /usr/bin/env python

import sys
import numpy as np
import math as mat
from tabulate import tabulate

if len(sys.argv) != 3 :
	print "Uso: python script.py pcapFile modeloAUtilizar(0/1)\n Donde modeloAUtilizar es 0 si no se distinguen los host y 1 en caso contrario. "
	sys.exit()

def esBroadcast(packet):
	return packet.dst == "ff:ff:ff:ff:ff:ff"

def pertenece(string, list):
	for s in list:
		if s == string:
			return True

	return False

def hacerTupla(first, second):
	return (first,second)

#Precondicion: simbolo pertenece a simbolos
def indiceDeSimbolo(simbolo, simbolos):
	for i in range(0,len(simbolos)) :
		if simbolo == simbolos[i]:
			return i

#entran < proba, simbolo >
def entropia( listaProbabilidadesPorSimbolo ):
	res = 0
	for s in listaProbabilidadesPorSimbolo:
		res -= s[0] * mat.log( s[0], 2)

	return res	 

def informacionPorSimbolo(simbolos, listaProbabilidadesPorSimbolo):
	res = []
	for i in range (0, len(simbolos)):
		informacion = (-1) * mat.log( listaProbabilidadesPorSimbolo[i][0], 2)
		res.append( hacerTupla(simbolos[i], informacion) )
	return res

from scapy.all import *

if __name__ == "__main__":

	print "Leyendo archivo..."
	pcapFile = rdpcap( sys.argv[1] )
	modeloAUtilizar = sys.argv[2]
	totalDePaquetes = 0
	broadcastCount = 0
	unicastCount = 0
	protocolos = []
	simbolosPosibles = []
	#horrible pero bue, 50 tienen que alcanzar
	contadoresDeSimbolos = np.zeros(50)
	 
	broadcast = "BROADCAST"
	unicast = "UNICAST"

	print "Analizando la fuente..."

	if (modeloAUtilizar == "0"):
		
		for packet in pcapFile:

			totalDePaquetes += 1
			primerComponente = ""
			protocolo = packet.payload.name

			if esBroadcast(packet):
				broadcastCount += 1
				primerComponente = broadcast
			else:
				unicastCount += 1
				primerComponente = unicast

			if not pertenece(protocolo, protocolos):
				#print("entro alguna vez al if not")
				protocolos.append(protocolo) 
				simbolosPosibles.append( hacerTupla(broadcast, protocolo) )
				simbolosPosibles.append( hacerTupla(unicast, protocolo) )

			simbolo = hacerTupla(primerComponente, protocolo)
			contadoresDeSimbolos[indiceDeSimbolo(simbolo, simbolosPosibles)] += 1
	else: 
		pass	
		#TODO modelo que distingue por ARP.dst, creo que es solo filtrar los ARP y hacer: packet.payload.dst


	#Filtro los que no tienen proba 0 
	simbolos = []
	probabilidadesSimbolos = []
	for i in range(0, len(simbolosPosibles)): 
		
		if contadoresDeSimbolos[i] != 0 :
			simbolos.append(simbolosPosibles[i])
			probaSimbolo = contadoresDeSimbolos[i] / totalDePaquetes
			probabilidadesSimbolos.append( hacerTupla(probaSimbolo, simbolosPosibles[i]) )

	
	#Impresiones
	print "Size de la muestra: " + str(totalDePaquetes)
	# print "Probabilidades por simbolo " 
	# print probabilidadesSimbolos
	
	# #print "Simbolos"
	# #print simbolos
	# #print contadoresDeSimbolos
	# assert(len(simbolos)== len(probabilidadesSimbolos))


	informacionXSimbolo = informacionPorSimbolo(simbolos, probabilidadesSimbolos)
	# print "INFORMACION POR SIMBOLO"
	# print informacionXSimbolo

	entropiaMuestral = entropia(probabilidadesSimbolos)	
	print "Entropia muestral: "
	print entropiaMuestral
	print "Entropia Maxima: "
	entropiaMaxima = 0
	for i in range(0, len(informacionXSimbolo)): 
		if informacionXSimbolo[i][1] > entropiaMaxima:
			entropiaMaxima = informacionXSimbolo[i][1]
	print entropiaMaxima
	# Imprime tabla a partir de los datos de 
	# una lista de listas:
	tabla = []
	for i in range(0, len(informacionXSimbolo)): 
		tabla.append([informacionXSimbolo[i][0],probabilidadesSimbolos[i][0],informacionXSimbolo[i][1]])
	print(tabulate(tabla, headers=['Simbolo', 'Probabilidad', 'Informacion']))

