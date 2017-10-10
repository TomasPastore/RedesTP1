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

#Formato: tabla[simbolo, probabilidad, informacion]
def rankearDistinguidosXInformacion(tablaOrdenadaXInfo):

	informacionesOrdenadas = []
	for linea in tablaOrdenadaXInfo:
		informacionesOrdenadas.append(linea[2])

	p1 = np.percentile(informacionesOrdenadas, 25)
	p3 = np.percentile(informacionesOrdenadas, 75)
	distinguidosA = []
	distinguidosB = []

	for linea in tablaOrdenadaXInfo:
		if linea[2]<= p1:
			distinguidosA.append(linea[0])
		elif linea[2]>= p3:
			distinguidosB.insert(0, linea[0])	
	
	ranking = []
	i = 0
	while i < max(len(distinguidosA),len(distinguidosB)):

		if i < len(distinguidosA) and i < len(distinguidosB):
			ranking.append([distinguidosA[i], distinguidosB[i]])
		elif i >= len(distinguidosA):
			ranking.append(["-----------", distinguidosB[i]])
		else:
			ranking.append([distinguidosA[i],"-----------"])
		i+=1

	print "\nRanking de simbolos distinguidos segun la informacion que aportan acerca de la fuente..."
	print "Distinguidos clase A: Simbolos cuya informacion se encuentra por debajo del primer percentil. A menor informacion, mas distinguido entre los de la clase A."
	print "Distinguidos clase B: Simbolos cuya informacion se encuentra por encima del tercer percentil. A mayor informacion, mas distinguido entre los de la clase B.\n"
	print(tabulate(ranking, headers=['Distinguidos clase A (de mas distinguido a menos distinguido)', 'Distinguidos clase B (de mas distinguido a menos distinguido)']))

from scapy.all import *

def main(archivo,modeloAUtilizar):
	print "Leyendo archivo..."
	pcapFile = rdpcap( archivo )
	totalDePaquetes = 0
	broadcastCount = 0
	unicastCount = 0
	protocolos = set()
	simbolosPosibles = set()
	contadorDeSimbolos = {}
	 
	broadcast = "BROADCAST"
	unicast = "UNICAST"

	print "Analizando la fuente..."

	if (modeloAUtilizar == 1):
		
		totalDePaquetes = len(pcapFile)
		
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
	
	elif (modeloAUtilizar == 2): 
		
		for packet in pcapFile:
			
			if packet.payload.name == "ARP" and esBroadcast(packet):
				
				totalDePaquetes += 1
				simbolo = packet.payload.pdst
				simbolosPosibles.add(simbolo)
			
				if simbolo in contadorDeSimbolos:
					contadorDeSimbolos[simbolo] += 1
				else:
					contadorDeSimbolos[simbolo] = 1
		
	else:
		#Esto en realidad no se ejecuta porque se chequea antes pero lo dejo por las dudas.
		print "Uso incorrecto, el segundo parametro deber ser 1 o 2."
		print "Uso: python script.py pcapFile modeloAUtilizar(1/2)\nDonde modeloAUtilizar es 1 si no se distinguen los host y 2 en caso contrario. "
		sys.exit()

	probaPorSimbolo = dict((key, float(value)/totalDePaquetes) for (key,value) in contadorDeSimbolos.items())
	informacionXSimbolo = informacionPorSimbolo(probaPorSimbolo)
	
	return (probaPorSimbolo,informacionXSimbolo,totalDePaquetes,broadcastCount,protocolos)

def armarTabla(probabilidades,informaciones,cantidadDePaquetes,cantidadBroadcast,protocolos):
	#Impresiones

	entropiaMuestral = entropia(probabilidades)
	entropiaMaxima = 0
	if len(probabilidades) > 0:
		entropiaMaxima = mat.log(len(probabilidades),2)
	print "\nSize de la muestra: " + str(cantidadDePaquetes)
	print " "	
	
	tabla = []
	for s,p in probabilidades.items(): 
		tabla.append([s,p,informaciones[s]])
	
	#ordena por informacion de forma creciente
	tabla.sort(key=lambda linea : linea[2], reverse = False)

	print(tabulate(tabla, headers=['Simbolo', 'Probabilidad', 'Informacion']))

	print "\nEntropia muestral: "
	print "\t\t",entropiaMuestral
	print "Entropia Maxima: "
	print "\t\t",entropiaMaxima
	
	if ( int(sys.argv[2] )==1):
		print "Porcentaje de tráfico broadcast: "
		print "\t\t",str(float(cantidadBroadcast)/cantidadDePaquetes) + "%"

	print " "

	if(len(probabilidades)>0):
		print "¿Desea ver un ranking de los simbolos distinguidos?(S/N)"
		respuesta = ""
		while True:
			respuesta = raw_input()

			if respuesta == "S":
				rankearDistinguidosXInformacion(tabla)
				#A mayor informacion menor probabilidad
				sys.exit()
			elif respuesta == "N":
				sys.exit()
			else:
				print "Entrada inválida."

if __name__ == '__main__':
	if len(sys.argv) != 3 or (int(sys.argv[2])!= 1 and int(sys.argv[2])!=2) :
		print "Uso: python script.py pcapFile modeloAUtilizar(1/2)\nDonde modeloAUtilizar es 1 si no se distinguen los host y 2 en caso contrario. "
		sys.exit()
	else:
		armarTabla(*main(sys.argv[1],int(sys.argv[2])))
		

