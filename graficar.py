#! /usr/bin/env python
#For Python, this file uses encoding: utf-8

import numpy as np
import matplotlib.pyplot as plt
import script
import math
from itertools import cycle

tableau20 = [(31, 119, 180), (174, 199, 232), (255, 127, 14), (255, 187, 120),  
			 (44, 160, 44), (152, 223, 138), (214, 39, 40), (255, 152, 150),  
			 (148, 103, 189), (197, 176, 213), (140, 86, 75), (196, 156, 148),  
			 (227, 119, 194), (247, 182, 210), (127, 127, 127), (199, 199, 199),  
			 (188, 189, 34), (219, 219, 141), (23, 190, 207), (158, 218, 229)]
			 
# Tableau Color Blind 10
tableau20blind = [(0, 107, 164), (255, 128, 14), (171, 171, 171), (89, 89, 89),
			 (95, 158, 209), (200, 82, 0), (137, 137, 137), (163, 200, 236),
			 (255, 188, 121), (207, 207, 207)]
  
# Rescale to values between 0 and 1 
for i in range(len(tableau20)):  
	r, g, b = tableau20[i]  
	tableau20[i] = (r / 255., g / 255., b / 255.)

for i in range(len(tableau20blind)):  
	r, g, b = tableau20blind[i]  
	tableau20blind[i] = (r / 255., g / 255., b / 255.)

def main():

	datos = script.main("wiredlabo.pcap",0)
	armar_grafico_comparador(*datos)
	armar_pie_chart_broadcast(*datos)
	armar_pie_chart_por_protocolo(*datos)

	plt.show()

def armar_pie_chart_por_protocolo(probabilidades,informaciones,cantidad_de_paquetes,cantidad_broadcast,protocolos):
	fig,ax = plt.subplots()
	protocolos = list(protocolos)
	probas = []

	for p in protocolos:
		cant_por_broadcast = 0
		cant_por_unicast = 0
		if ("BROADCAST",p) in probabilidades:
			cant_por_broadcast = probabilidades[("BROADCAST",p)]
		if ("UNICAST",p) in probabilidades:
			cant_por_unicast = probabilidades[("UNICAST",p)]
		
		probas.append(cant_por_broadcast+cant_por_unicast)

	colors = []
	iterador = cycle(tableau20)
	for i in range(len(protocolos)):
		colors.append(iterador.next())

	ax.pie(probas,labels=protocolos, autopct='%1.1f%%',
        startangle=90,colors=colors,
        labeldistance=1.1)
	ax.axis('equal')


def armar_pie_chart_broadcast(probabilidades,informaciones,cantidad_de_paquetes,cantidad_broadcast,protocolos):
	fig,ax = plt.subplots(figsize=(10,10))

	labels = ['Total', 'Paquetes broadcast']

	colors = [tableau20[0],tableau20[1]]

	sizes = [cantidad_de_paquetes-cantidad_broadcast,cantidad_broadcast]
	ax.pie(sizes,labels=labels, autopct='%1.1f%%',
        startangle=90,colors=colors,
        labeldistance=0.2)
	ax.axis('equal')


def armar_grafico_comparador(probabilidades,informaciones,cantidad_de_paquetes,cantidad_broadcast,protocolos):
	
	fig, ax = plt.subplots(figsize=(20, 10))
	#ax.grid(True)

	bar_width = 0.9
	ind = np.arange(len(probabilidades))

	dashes = [20, 5, 15, 5]

	rects = ax.bar(ind, informaciones.values(), bar_width,alpha=0.85)
	entropia_maxima = math.log(len(probabilidades),2)

	max_entropy = ax.axhline(y=entropia_maxima, xmin=0, xmax=len(probabilidades), 
		color='g',linewidth=1.7,label=u"Entropía máxima")

	entropy = ax.axhline(y=script.entropia(probabilidades), xmin=0, xmax=len(probabilidades), 
		color='red',linewidth=1.7,label=u'Entropía')

	max_entropy.set_dashes(dashes)

	entropy.set_dashes(dashes)

	ax.set_title(u"Información por símbolo - Entropía - Entropía Máxima")

	ax.set_xlabel(u"Símbolos")
	ax.set_ylabel(u"Información")

	ax.set_xticks([])
	ax.set_yticks(np.arange(max(informaciones.values())+1))

	ax.legend(fancybox=True,loc='best')


	keys = informaciones.iterkeys()
	colors = cycle(tableau20)
	for rect in rects:
		height = rect.get_height()
		rect.set_color(colors.next())
		d,p = keys.next()
		clave = d+"\n"+p
		ax.text(rect.get_x() + rect.get_width()/2., 0.4*height,
				clave,
				ha='center', va='bottom')

if __name__ == '__main__':
	main()