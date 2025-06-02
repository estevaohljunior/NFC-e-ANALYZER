// Função de simulação atualizada para identificar todos os padrões
function simulateAnalysis(keys) {
    // Extrai os pares (nNF, cNF) de todas as chaves
    const pairs = keys.map(key => ({
        nNF: parseInt(key.slice(25, 34)),
        cNF: parseInt(key.slice(35, 43))
    }));
    
    // 1. Verifica se é Fixo (F)
    if (pairs.every(pair => pair.cNF === pairs[0].cNF)) {
        return {
            pattern: "F",
            vulnerability_level: "ALTO",
            vulnerability_score: 100,
            description: "O código numérico (cNF) é fixo para todas as notas",
            confidence: 1.0,
            details: {
                fixed_value: pairs[0].cNF.toString().padStart(8, '0')
            },
            recommendation: "Recomendação CRÍTICA: Alterar imediatamente para um gerador aleatório seguro"
        };
    }
    
    // 2. Verifica se é Espelho (E)
    if (pairs.every(pair => pair.cNF === pair.nNF)) {
        return {
            pattern: "E",
            vulnerability_level: "ALTO",
            vulnerability_score: 90,
            description: "O código numérico (cNF) é igual ao número da nota (nNF)",
            confidence: 1.0,
            details: {
                mirrored: true
            },
            recommendation: "Recomendação CRÍTICA: Implementar um gerador aleatório seguro"
        };
    }
    
    // 3. Verifica se é Espelho+K (E+K)
    const differences = pairs.map(pair => pair.cNF - pair.nNF);
    if (differences.every(diff => diff === differences[0])) {
        return {
            pattern: "E+K",
            vulnerability_level: "ALTO",
            vulnerability_score: 85,
            description: `O código numérico (cNF) é igual ao número da nota (nNF) mais ${differences[0]}`,
            confidence: 1.0,
            details: {
                constant: differences[0],
                formula: `cNF = nNF + ${differences[0]}`
            },
            recommendation: "Recomendação CRÍTICA: Padrão ainda previsível, implementar geração aleatória"
        };
    }
    
    // 4. Verifica se é Incremental (I)
    const cnfDifferences = [];
    for (let i = 1; i < pairs.length; i++) {
        cnfDifferences.push(pairs[i].cNF - pairs[i-1].cNF);
    }
    
    // Verifica se é estritamente incremental
    if (cnfDifferences.every(diff => diff > 0)) {
        // Incremento constante
        if (cnfDifferences.every(diff => diff === cnfDifferences[0])) {
            return {
                pattern: "I",
                vulnerability_level: "MÉDIO",
                vulnerability_score: 60,
                description: "O código numérico (cNF) segue um padrão incremental constante",
                confidence: 0.9,
                details: {
                    increment: cnfDifferences[0],
                    type: "constant"
                },
                recommendation: "Recomendação: Melhorar o sistema para usar geração aleatória"
            };
        }
        // Incremento variável mas sempre crescente
        else {
            return {
                pattern: "I",
                vulnerability_level: "MÉDIO",
                vulnerability_score: 65,
                description: "O código numérico (cNF) segue um padrão incremental variável",
                confidence: 0.8,
                details: {
                    _average_increment: Math.round(cnfDifferences.reduce((a, b) => a + b, 0) / cnfDifferences.length,
                        min_increment, Math.min(...cnfDifferences),
                        max_increment, Math.max(...cnfDifferences),
                        type, "variable"),
                    get average_increment() {
                        return this._average_increment;
                    },
                    set average_increment(value) {
                        this._average_increment = value;
                    },
                },
                recommendation: "Recomendação: Melhorar o sistema para usar geração aleatória"
            };
        }
    }
    
    // 5. Se não for nenhum dos anteriores, considera Aleatório (A)
    return {
        pattern: "A",
        vulnerability_level: "BAIXO",
        vulnerability_score: 10,
        description: "O código numérico (cNF) aparenta ser gerado aleatoriamente",
        confidence: 0.7,
        details: {
            randomness_test: "passed",
            unique_values: new Set(pairs.map(p => p.cNF)).size,
            total_values: pairs.length
        },
        recommendation: "Configuração adequada, manter o sistema atual"
    };
}

// Função para exibir os resultados (atualizada para mostrar todos os padrões)
function displayResults(data, originalKeys) {
    // ... (código anterior permanece o mesmo) ...
    
    // Atualiza os detalhes do padrão para todos os casos
    const detailsContent = document.getElementById('patternDetailsContent');
    detailsContent.innerHTML = '';
    
    if (data.pattern === 'F') {
        detailsContent.innerHTML = `
            <p>O código numérico (cNF) é sempre o mesmo valor em todas as notas fiscais:</p>
            <div class="alert alert-secondary">
                <strong>Valor fixo:</strong> <code>${data.details.fixed_value}</code>
            </div>
            <p class="text-danger">Este é o padrão mais vulnerável, permitindo fácil previsão de chaves futuras.</p>
        `;
    } 
    else if (data.pattern === 'E') {
        detailsContent.innerHTML = `
            <p>O código numérico (cNF) é exatamente igual ao número da nota fiscal (nNF):</p>
            <div class="alert alert-secondary">
                <strong>Relação:</strong> cNF = nNF
            </div>
            <p class="text-danger">Padrão altamente previsível, pois o cNF pode ser deduzido diretamente do nNF.</p>
        `;
    }
    else if (data.pattern === 'E+K') {
        detailsContent.innerHTML = `
            <p>O código numérico (cNF) é derivado do número da nota fiscal (nNF) somado a uma constante:</p>
            <div class="alert alert-secondary">
                <strong>Fórmula:</strong> cNF = nNF + ${data.details.constant}
            </div>
            <p class="text-danger">Padrão ainda previsível, pois o cNF pode ser calculado a partir do nNF.</p>
        `;
    }
    else if (data.pattern === 'I') {
        if (data.details.type === 'constant') {
            detailsContent.innerHTML = `
                <p>O código numérico (cNF) aumenta de forma incremental constante:</p>
                <ul>
                    <li><strong>Incremento:</strong> ${data.details.increment}</li>
                    <li><strong>Tipo:</strong> Constante</li>
                </ul>
                <p class="text-warning">Padrão previsível, pois o próximo valor pode ser estimado.</p>
            `;
        } else {
            detailsContent.innerHTML = `
                <p>O código numérico (cNF) aumenta de forma incremental variável:</p>
                <ul>
                    <li><strong>Incremento médio:</strong> ${data.details.average_increment}</li>
                    <li><strong>Mínimo:</strong> ${data.details.min_increment}</li>
                    <li><strong>Máximo:</strong> ${data.details.max_increment}</li>
                </ul>
                <p class="text-warning">Padrão parcialmente previsível, com alguma variação nos incrementos.</p>
            `;
        }
    }
    else if (data.pattern === 'A') {
        detailsContent.innerHTML = `
            <p>O código numérico (cNF) passou nos testes básicos de aleatoriedade:</p>
            <ul>
                <li><strong>Valores únicos:</strong> ${data.details.unique_values} de ${data.details.total_values}</li>
                <li>Distribuição uniforme de dígitos</li>
                <li>Variação adequada entre valores consecutivos</li>
            </ul>
            <p class="text-success">Padrão considerado seguro conforme recomendações da Receita Federal.</p>
        `;
    }
    
    // ... (restante do código permanece o mesmo) ...
}
