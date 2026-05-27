import os
import re
import email
import shutil
from email import policy
from email.parser import BytesParser


# Palabras que suelen aparecer en phishing con un peso de riesgo, cuanto más alto el número, más sospechosa es la palabra
PALABRAS_SPAM = {
    # Urgencia
    "urgente": 40, "urgentemente": 40, "inmediatamente": 35,
    "actúa ahora": 50, "actua ahora": 50, "última oportunidad": 45,
    "expira hoy": 50, "caduca hoy": 50, "tiempo limitado": 35,
    # Premios y dinero
    "premio": 50, "ganador": 50, "has ganado": 60, "lotería": 55,
    "millones": 40, "dinero gratis": 65, "transferencia": 35,
    "herencia": 55, "inversión garantizada": 60,
    # Phishing de credenciales
    "contraseña": 45, "password": 45, "usuario": 30,
    "verifica tu cuenta": 60, "confirma tu cuenta": 60,
    "acceso suspendido": 55, "cuenta bloqueada": 55,
    "datos bancarios": 65, "tarjeta de crédito": 50,
    "número de cuenta": 55, "pin": 40, "cvv": 65,
    # Links sospechosos
    "haz clic aquí": 45, "haz click aqui": 45, "enlace seguro": 30,
    "descarga ahora": 40, "instala ahora": 45, "actualiza ahora": 40,
    # Spam comercial típico
    "oferta exclusiva": 30, "gratis": 25, "sin coste": 25,
    "100% gratis": 40, "descuento especial": 20,
    # Palabras en inglés que también aparecen
    "free": 20, "winner": 50, "click here": 45, "verify account": 60,
    "suspended": 45, "confirm password": 65, "bank account": 50,
    "credit card": 45, "limited time": 35, "act now": 50,
}

# Dominios reales que suelen imitar los atacantes
DOMINIOS_LEGITIMOS = [
    "google.com", "gmail.com", "yahoo.com", "outlook.com", "hotmail.com",
    "microsoft.com", "apple.com", "icloud.com", "amazon.com", "paypal.com",
    "ebay.com", "facebook.com", "instagram.com", "twitter.com", "linkedin.com",
    "bankinter.com", "caixabank.com", "santander.com", "bbva.com", "ing.com",
    "correos.es", "hacienda.gob.es", "seg-social.es", "agenciatributaria.es",
]

# Dominios que son sospechosos en la vida real, si los buscas están
DOMINIOS_MALOS = [
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "t.co",
    "mailinator.com", "tempmail.com", "guerrillamail.com",
]

class NodoBST:
    # Cada nodo guarda una palabra, su peso de riesgo y cuántas veces aparece
    def __init__(self, palabra, peso):
        self.palabra = palabra
        self.peso = peso
        self.frecuencia = 1   # la primera vez que la ponemos
        self.izquierdo = None
        self.derecho = None

class ArbolBST:
    # Árbol BST para guardar las palabras sospechosas
    #Usaamos _ en los métodos internos para indicar que son privados

    def __init__(self):
        self.raiz = None

    def insertar(self, palabra, peso):
        self.raiz = self._insertar(self.raiz, palabra.lower(), peso)

    def _insertar(self, nodo, palabra, peso):
        # caso base: posición vacía, creamos el nodo aquí
        if nodo is None:
            return NodoBST(palabra, peso)
        if palabra < nodo.palabra:
            nodo.izquierdo = self._insertar(nodo.izquierdo, palabra, peso)
        elif palabra > nodo.palabra:
            nodo.derecho = self._insertar(nodo.derecho, palabra, peso)
        else:
            # ya estaba en el árbol, solo sumamos una aparición más
            nodo.frecuencia += 1
        return nodo

    def buscar(self, palabra):
        return self._buscar(self.raiz, palabra.lower())

    def _buscar(self, nodo, palabra):
        if nodo is None or nodo.palabra == palabra:
            return nodo
        if palabra < nodo.palabra:
            return self._buscar(nodo.izquierdo, palabra)
        return self._buscar(nodo.derecho, palabra)

    def calcular_riesgo_total(self):
        return self._calcular_riesgo(self.raiz)

    def _calcular_riesgo(self, nodo):
        if nodo is None:
            return 0
        izq = self._calcular_riesgo(nodo.izquierdo)
        actual = nodo.peso * nodo.frecuencia
        der = self._calcular_riesgo(nodo.derecho)
        return izq + actual + der

    def palabras_encontradas(self):
        resultado = []
        self._listar(self.raiz, resultado)
        return resultado

    def _listar(self, nodo, lista):
        if nodo is None:
            return
        self._listar(nodo.izquierdo, lista)
        lista.append((nodo.palabra, nodo.peso, nodo.frecuencia))
        self._listar(nodo.derecho, lista)

class FiltroCorreo: # Clase base para todos los filtros
    # Cada filtro recibe el contenido del correo y devuelve una puntuación de riesgo
    def analizar(self, asunto, remitente, cuerpo):
        pass

class FiltroPorPalabrasClave(FiltroCorreo): # Busca palabras sospechosas en el correo usando el árbol BST

    def __init__(self):
        # cargamos las palabras sospechosas en el árbol al crear el filtro
        self.arbol = ArbolBST()
        for palabra, peso in PALABRAS_SPAM.items():
            self.arbol.insertar(palabra, peso)

    def analizar(self, asunto, remitente, cuerpo):
        texto = (asunto + " " + cuerpo).lower()
        arbol_encontradas = ArbolBST()
        razones = []

        for palabra, peso in PALABRAS_SPAM.items():
            if palabra in texto:
                arbol_encontradas.insertar(palabra, peso)

        puntuacion = arbol_encontradas.calcular_riesgo_total()

        for palabra, peso, freq in arbol_encontradas.palabras_encontradas():
            razones.append(f"Palabra sospechosa: '{palabra}' (peso {peso}, aparece {freq}x)")

        return puntuacion, razones

class FiltroPorRemitenteSospechoso(FiltroCorreo):

class AnalizadorCorreo: