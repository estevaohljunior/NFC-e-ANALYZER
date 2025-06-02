from flask import Flask, request, jsonify, render_template
from typing import List, Dict, Tuple, Optional
import re
import numpy as np
from collections import Counter
from statistics import stdev, mean
import math

app = Flask(__name__)

class NFCeAnalyzer:
    def __init__(self):
        self.vulnerability_levels = {
            'F': {'level': 'ALTO', 'score': 100},      # Fixo
            'E': {'level': 'ALTO', 'score': 90},       # Espelho
            'E+K': {'level': 'ALTO', 'score': 85},    # Espelho + Constante
            'I': {'level': 'MÉDIO', 'score': 60},     # Incremental
            'A': {'level': 'BAIXO', 'score': 10},      # Aleatório
            'INDETERMINADO': {'level': 'DESCONHECIDO', 'score': 50}
        }
        
        # Configuração de thresholds para detecção de padrões
        self.thresholds = {
            'randomness': 0.7,  # Limiar para considerar como aleatório
            'increment_variation': 0.2  # Variação permitida para incrementais
        }

    def extract_components(self, key: str) -> Dict:
        """Extrai os componentes de uma chave de acesso.
        
        Args:
            key: Chave de acesso de 44 dígitos
            
        Returns:
            Dicionário com os componentes extraídos
            
        Raises:
            ValueError: Se a chave for inválida
        """
        if not self._validate_key(key):
            raise ValueError("Formato de chave inválido. Deve conter exatamente 44 dígitos.")
        
        return {
            'cUF': key[0:2],
            'AAMM': key[2:6],
            'CNPJ': key[6:20],
            'mod': key[20:22],
            'serie': key[22:25],
            'nNF': key[25:34],
            'tpEmis': key[34:35],
            'cNF': key[35:43],
            'cDV': key[43:44]
        }

    def _validate_key(self, key: str) -> bool:
        """Valida o formato da chave de acesso.
        
        Args:
            key: Chave de acesso a ser validada
            
        Returns:
            True se a chave for válida, False caso contrário
        """
        return bool(re.match(r'^\d{44}$', key))

    def analyze_pattern(self, keys: List[str]) -> Dict:
        """Analisa o padrão de geração do cNF nas chaves fornecidas.
        
        Args:
            keys: Lista de chaves de acesso da mesma empresa
            
        Returns:
            Dicionário com os resultados da análise contendo:
            - pattern: Padrão identificado
            - vulnerability_level: Nível de vulnerabilidade
            - description: Descrição do padrão
            - confidence: Nível de confiança na detecção
            - details: Detalhes adicionais sobre o padrão
            
        Raises:
            ValueError: Se a lista estiver vazia ou chaves forem de empresas diferentes
        """
        if not keys:
            raise ValueError("Lista de chaves vazia")

        try:
            components = [self.extract_components(key) for key in keys]
        except ValueError as e:
            raise ValueError(f"Chave inválida encontrada: {str(e)}")

        # Verifica se todas as chaves são da mesma empresa
        cnpj = components[0]['CNPJ']
        if not all(comp['CNPJ'] == cnpj for comp in components):
            raise ValueError("Todas as chaves devem ser da mesma empresa")

        # Análise do padrão
        cnf_values = [int(comp['cNF']) for comp in components]
        nnf_values = [int(comp['nNF']) for comp in components]

        pattern, details = self._identify_pattern(cnf_values, nnf_values)
        vuln_info = self.vulnerability_levels.get(pattern, self.vulnerability_levels['INDETERMINADO'])
        
        return {
            'pattern': pattern,
            'vulnerability_level': vuln_info['level'],
            'vulnerability_score': vuln_info['score'],
            'description': self._get_pattern_description(pattern),
            'confidence': self._calculate_confidence(pattern, cnf_values, nnf_values),
            'details': details,
            'recommendation': self._get_recommendation(pattern)
        }

    def _identify_pattern(self, cnf_values: List[int], nnf_values: List[int]) -> Tuple[str, Dict]:
        """Identifica o padrão de geração do cNF.
        
        Args:
            cnf_values: Lista de valores cNF
            nnf_values: Lista de valores nNF correspondentes
            
        Returns:
            Tupla contendo (padrão identificado, detalhes do padrão)
        """
        if len(cnf_values) == 1:
            return 'INDETERMINADO', {'reason': 'Apenas uma chave fornecida'}

        # Verifica se é fixo
        if all(v == cnf_values[0] for v in cnf_values):
            return 'F', {'fixed_value': cnf_values[0]}

        # Verifica se é espelho
        if all(c == n for c, n in zip(cnf_values, nnf_values)):
            return 'E', {'mirrored': True}

        # Verifica se é espelho + constante
        differences = [c - n for c, n in zip(cnf_values, nnf_values)]
        if all(d == differences[0] for d in differences):
            return 'E+K', {'constant': differences[0]}

        # Verifica se é incremental
        incremental_result = self._check_incremental_pattern(cnf_values)
        if incremental_result:
            return incremental_result

        # Verifica padrões aleatórios
        if self._check_random_pattern(cnf_values):
            return 'A', {'randomness_test': 'passed'}

        # Padrão não identificado claramente
        return '?', {'reason': 'Padrão complexo não identificado'}

    def _check_incremental_pattern(self, cnf_values: List[int]) -> Optional[Tuple[str, Dict]]:
        """Verifica se os valores seguem um padrão incremental.
        
        Args:
            cnf_values: Lista de valores cNF
            
        Returns:
            Tupla (padrão, detalhes) se for incremental, None caso contrário
        """
        if len(cnf_values) < 2:
            return None
        
        differences = [cnf_values[i] - cnf_values[i-1] for i in range(1, len(cnf_values))]
        
        # Incremento constante
        if all(d == differences[0] for d in differences):
            return 'I', {'increment': differences[0], 'type': 'constant'}
        
        # Incremento variável mas sempre crescente
        if all(d > 0 for d in differences):
            avg_increment = round(mean(differences))
            increment_variation = stdev(differences) / avg_increment if avg_increment != 0 else 0
            
            if increment_variation < self.thresholds['increment_variation']:
                return 'I', {
                    'average_increment': avg_increment,
                    'increment_variation': increment_variation,
                    'type': 'variable_but_consistent'
                }
        
        return None

    def _check_random_pattern(self, cnf_values: List[int]) -> bool:
        """Realiza testes básicos de aleatoriedade nos valores cNF.
        
        Args:
            cnf_values: Lista de valores cNF
            
        Returns:
            True se os valores parecem aleatórios, False caso contrário
        """
        if len(cnf_values) < 5:
            return False
        
        # Teste de repetição - valores únicos
        unique_ratio = len(set(cnf_values)) / len(cnf_values)
        
        # Teste de distribuição de dígitos
        digit_counts = Counter(''.join(map(str, cnf_values)))
        digit_uniformity = stdev(digit_counts.values()) / mean(digit_counts.values()) if mean(digit_counts.values()) != 0 else 0
        
        # Teste de diferenças consecutivas
        diffs = [abs(cnf_values[i] - cnf_values[i-1]) for i in range(1, len(cnf_values))]
        avg_diff = mean(diffs)
        diff_uniformity = stdev(diffs) / avg_diff if avg_diff != 0 else 0
        
        # Combina os testes
        randomness_score = (unique_ratio + (1 - digit_uniformity) + (1 - diff_uniformity)) / 3
        
        return randomness_score > self.thresholds['randomness']

    def _calculate_confidence(self, pattern: str, cnf_values: List[int], nnf_values: List[int]) -> float:
        """Calcula um nível de confiança na detecção do padrão.
        
        Args:
            pattern: Padrão identificado
            cnf_values: Valores cNF analisados
            nnf_values: Valores nNF correspondentes
            
        Returns:
            Nível de confiança entre 0 (baixo) e 1 (alto)
        """
        if pattern == 'INDETERMINADO':
            return 0.0
        
        n = len(cnf_values)
        if n < 2:
            return 0.0
        
        if pattern in ['F', 'E', 'E+K']:
            # Padrões exatos - confiança alta se todos os casos baterem
            return 1.0 if n >= 3 else 0.8
        
        if pattern == 'I':
            # Para incrementais, calcula baseado na consistência
            diffs = [cnf_values[i] - cnf_values[i-1] for i in range(1, n)]
            consistency = 1 - (stdev(diffs) / mean(diffs)) if mean(diffs) != 0 else 0
            return max(0, min(1, consistency * (1 + math.log(n)/10)))
        
        if pattern == 'A':
            # Para aleatórios, baseado nos testes estatísticos
            return self._check_random_pattern(cnf_values) * 0.8 + (n/20) * 0.2
        
        return 0.5  # Padrão desconhecido - confiança média

    def _get_pattern_description(self, pattern: str) -> str:
        """Retorna a descrição do padrão identificado."""
        descriptions = {
            'F': 'O código numérico (cNF) é fixo para todas as notas',
            'E': 'O código numérico (cNF) é igual ao número da nota (nNF)',
            'E+K': 'O código numérico (cNF) é igual ao número da nota (nNF) mais uma constante',
            'I': 'O código numérico (cNF) segue um padrão incremental',
            'A': 'O código numérico (cNF) aparenta ser gerado aleatoriamente',
            'INDETERMINADO': 'Não foi possível determinar o padrão com apenas uma chave',
            '?': 'Padrão complexo não identificado pelos testes atuais'
        }
        return descriptions.get(pattern, 'Padrão desconhecido')

    def _get_recommendation(self, pattern: str) -> str:
        """Retorna uma recomendação baseada no padrão identificado."""
        recommendations = {
            'F': 'Recomendação CRÍTICA: Alterar imediatamente para um gerador aleatório seguro',
            'E': 'Recomendação CRÍTICA: Implementar um gerador aleatório seguro',
            'E+K': 'Recomendação CRÍTICA: Padrão ainda previsível, implementar geração aleatória',
            'I': 'Recomendação: Melhorar o sistema para usar geração aleatória',
            'A': 'Configuração adequada, manter o sistema atual',
            'INDETERMINADO': 'Coletar mais amostras para análise precisa',
            '?': 'Análise mais aprofundada necessária'
        }
        return recommendations.get(pattern, 'Consulte um especialista em segurança')

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze_keys():
    """Endpoint para análise de chaves de acesso."""
    try:
        data = request.get_json()
        if not data or 'keys' not in data:
            return jsonify({'error': 'Nenhuma chave fornecida'}), 400

        analyzer = NFCeAnalyzer()
        result = analyzer.analyze_pattern(data['keys'])
        
        # Log simplificado para produção (remover valores sensíveis)
        log_data = {k: v for k, v in result.items() if k not in ['details']}
        app.logger.info(f"Análise concluída: {log_data}")
        
        return jsonify(result)

    except ValueError as e:
        app.logger.warning(f"Erro de validação: {str(e)}")
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        app.logger.error(f"Erro interno: {str(e)}", exc_info=True)
        return jsonify({'error': 'Erro interno do servidor'}), 500

if __name__ == '__main__':
    app.run(debug=True)
    
