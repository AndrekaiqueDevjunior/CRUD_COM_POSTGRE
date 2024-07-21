document.getElementById('connectButton').addEventListener('click', function() {
    fetch('/connect')
        .then(response => response.json())
        .then(data => {
            const resultDiv = document.getElementById('result');
            if (data.success) {
                resultDiv.textContent = `Conexão bem-sucedida! Versão do PostgreSQL: ${data.version}`;
            } else {
                resultDiv.textContent = `Erro: ${data.error}`;
            }
        })
        .catch(error => {
            document.getElementById('result').textContent = `Erro na solicitação: ${error}`;
        });
});
