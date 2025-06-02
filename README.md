# NFC-e-ANALYZER

## Análise de Vulnerabilidades em Chaves de Acesso de Notas Fiscais Eletrônicas (NFC-e)


### 📋 Sobre o Projeto
Este projeto de pesquisa investiga vulnerabilidades de segurança na geração de chaves de acesso de Notas Fiscais de Consumidor Eletrônicas (NFC-e), com foco na proteção de dados empresariais e pessoais de consumidores.

### 🎯 Problema Identificado

Atualmente, cerca de 70 milhões de NFC-e são emitidas diariamente no Brasil, contendo dados sensíveis como:

•	Informações empresariais (vendas, faturamento, produtos)
•	Dados pessoais dos consumidores (nome, CPF, endereço, telefone)

Vulnerabilidade Crítica: Mais de 70% das empresas do varejo em Campina Grande-PB (dados de 2017) utilizam sistemas que geram chaves de acesso não aleatórias, violando as especificações de segurança da SEFAZ.

### 🔍 Metodologia de Análise

Classificação dos Algoritmos de Geração (cNF)
O projeto identifica e classifica os seguintes padrões vulneráveis:
1.	Fixo (F): Valor constante para todas as notas
2.	Espelho (E): cNF igual ao número da nota fiscal (nNF)
3.	Espelho+K (E+K): nNF somado a uma constante
4.	Incremental (I): Crescimento sequencial sem relação com nNF
5.	Aleatória (A): Geração usando PRNG (método seguro)

### 🎯 Objetivos
Objetivo Geral
Investigar se os sistemas utilizados por empresas do varejo atendem às normas de segurança de geração da chave de acesso da NFC-e.

### 🛠️ Componentes Técnicos

#### API REST de Análise
•	Entrada: Lista de chaves de acesso
•	Saída: Classificação do método de geração e nível de vulnerabilidade
•	Tecnologia: Framework backend maduro (Flask)

#### ⚠️ Riscos Identificados
#### Para Empresas
•	Exposição de dados comerciais sensíveis
•	Vulnerabilidade a extorsão e chantagem
•	Violação da LGPD (Lei Geral de Proteção de Dados)

#### Para Consumidores
•	Exposição de dados pessoais
•	Risco de golpes com boletos falsos
•	Uso indevido de informações pessoais

### 📊 Impacto Esperado
•	Relatório de alertas para governo, empresas, consumidores e contadores
•	Conscientização sobre vulnerabilidades no ecossistema fiscal
•	Propostas de melhorias para sistemas existentes

### 🔧 Metodologia de Execução

#### Coleta de Dados

1.	Aquisição de produtos em estabelecimentos variados
2.	Análise de DANFEs descartados
3.	Solicitação formal junto a estabelecimentos
4.	Consulta ao histórico pessoal na SEFAZ-PB

#### Análise Técnica
1.	Classificação dos algoritmos de geração
2.	Análise estatística comparativa (2017 vs 2024)
3.	Desenvolvimento e teste da API

### 📈 Relevância

#### Conformidade Legal

•	Alinhamento com a LGPD (Lei 13.709/2018)
•	Suporte às diretrizes de governo eletrônico
•	Fortalecimento da segurança fiscal nacional

#### Impacto Social
•	Proteção da privacidade dos consumidores
•	Segurança empresarial no ambiente digital
•	Modernização do ecossistema fiscal brasileiro
________________________________________
