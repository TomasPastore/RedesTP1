#! /usr/bin/env python
#For Python, this file uses encoding: utf-8

import numpy as np
import matplotlib.pyplot as plt
import script
import math
from itertools import cycle
import argparse

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

def main(filename,save):

	datos = script.main(filename,1)
	armar_grafico_comparador(filename,save,*datos)
	armar_pie_chart_broadcast(filename,save,*datos)
	armar_pie_chart_por_protocolo(filename,save,*datos)

	plt.show()

def armar_pie_chart_por_protocolo(filename,save,probabilidades,informaciones,cantidad_de_paquetes,cantidad_broadcast,protocolos):
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

	patches, texts = ax.pie(probas,startangle=90,colors=colors)

	labels = ['{0} - {1:1.2f} %'.format(i,j) for i,j in zip(protocolos, np.array(probas)*100.0)]

	patches, labels, dummy =  zip(*sorted(zip(patches, labels, probas),
                                          key=lambda x: x[2],
                                          reverse=True))

	ax.legend(patches, labels, loc='best',
           fontsize=15)

	for text in texts:
		text.set_fontsize(15)

	ax.axis('equal')

	if save:
		plt.savefig('graficos/'+filename.split('.')[0]+'_pie_s1.pdf',bbox_inches='tight')


def armar_pie_chart_broadcast(filename,save,probabilidades,informaciones,cantidad_de_paquetes,cantidad_broadcast,protocolos):
	fig,ax = plt.subplots(figsize=(10,10))

	labels = ['Paquetes Uni y multicast', 'Paquetes broadcast']

	colors = [tableau20[0],tableau20[1]]

	sizes = [cantidad_de_paquetes-cantidad_broadcast,cantidad_broadcast]
	patches, texts, autotexts = ax.pie(sizes,labels=labels, autopct='%1.1f%%',
        startangle=90,colors=colors,
        labeldistance=1.18,
        pctdistance=1.1)

	for text in texts:
		text.set_fontsize(15)

	for text in autotexts:
		text.set_fontsize(15)

	ax.axis('equal')

	if save:
		plt.savefig('graficos/'+filename.split('.')[0]+'_pie_broadcast_s1.pdf',bbox_inches='tight')



def armar_grafico_comparador(filename,save,probabilidades,informaciones,cantidad_de_paquetes,cantidad_broadcast,protocolos):
	
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
		color='red',linewidth=1.7,label=u'Entropía muestral')

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

	if save:
		plt.savefig('graficos/'+filename.split('.')[0]+'_info_entropia_s1.pdf',bbox_inches='tight')


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	#Para cuando quiero debuggear... pero mejor sin default xD
	#parser.add_argument("filename", help="Archivo de destino",action='store',nargs='?', default='wiredlabo.pcap')
	parser.add_argument("filename", help="Archivo de la captura",action='store')
	parser.add_argument("--save",'-s', help="Guardar los gráficos (debe existir la carpeta graficos)",action='store_true',
		default=False, dest='save')
	args = parser.parse_args()

	main(args.filename,args.save)