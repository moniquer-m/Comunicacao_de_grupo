# Projeto de Autenticação, Gerenciamento de Usuários e Simulador de Mensagens Distribuídas (Baseado em Privilégio)

## Descrição Concisa da Proposta

Este projeto integra um sistema robusto de autenticação e gerenciamento de usuários com um simulador de mensagens distribuídas baseado em privilégio. Utilizando Flask como framework web, o sistema oferece:

1. Uma solução segura e escalável para controle de acesso baseado em privilégios.
2. Uma ferramenta educacional interativa para compreensão de sistemas distribuídos.
3. Uma plataforma que demonstra a implementação prática de conceitos de segurança e distribuição de sistemas.

## Instalação e Configuração

Para configurar e executar este projeto em sua máquina local, siga os passos abaixo:

### Pré-requisitos

- Python 3.7 ou superior
- pip (gerenciador de pacotes do Python)
- Git (opcional, para clonar o repositório)

### Passos de Instalação

1. **Clone o repositório** (ou baixe o código-fonte):
2. **Crie um ambiente virtual** (recomendado):
python -m venv venv

3. **Ative o ambiente virtual**:
- No Windows:
  ```
  venv\Scripts\activate
  ```
- No macOS e Linux:
  ```
  source venv/bin/activate
  ```
4. **Instale as dependências necessárias**:
pip install flask
pip install flask-login
pip install passlib
5. **Execute a aplicação**:
python app.py
6. **Acesse a aplicação**:
Abra seu navegador e vá para `http://localhost:5000`

### Cliente (Frontend)

1. **Autenticação e Gerenciamento de Usuários**
   - Registro de novos usuários com validação de dados
   - Login seguro com proteção contra tentativas excessivas
   - Logout e gerenciamento de sessões
   - Visualização e edição de perfil de usuário
   - Acesso diferenciado baseado em papéis (admin, cliente, PQL)

2. **Simulador de Mensagens Distribuídas**
   - Inicialização da simulação com número predefinido de processos
   - Visualização em tempo real do estado de cada processo
   - Observação da troca de mensagens entre processos
   - Acompanhamento do processo detentor do token atual
   - Visualização das filas de mensagens de cada processo
   - Controle passo a passo da simulação

### Servidor (Backend)

1. **Autenticação e Gerenciamento de Usuários**
   - Processamento seguro de registro e autenticação de usuários
   - Geração e verificação de tokens de sessão
   - Armazenamento seguro de senhas utilizando Argon2
   - Gerenciamento de perfis de usuários (CRUD)
   - Implementação de controle de acesso baseado em papéis

2. **Simulador de Mensagens Distribuídas**
   - Implementação do algoritmo baseado em privilégio
   - Gerenciamento do estado de cada processo na simulação
   - Simulação de falhas aleatórias e recuperação de processos
   - Processamento e ordenação de mensagens recebidas
   - Geração de atualizações em tempo real do estado da simulação

## Comunicação Cliente-Servidor

A comunicação entre cliente e servidor é baseada em requisições HTTP/HTTPS, utilizando tanto métodos GET quanto POST, dependendo da operação:

1. **Sistema de Autenticação**
   - POST: `/login`, `/register`, `/update-profile`
   - GET: `/logout`, `/user-data`

2. **Simulador de Mensagens Distribuídas**
   - GET: `/distributed-messaging-simulator` (inicialização)
   - POST: `/step` (avanço da simulação)

### Diagrama de Sequência (Simulador)
Cliente Servidor (Flask) PrivilegeBasedAlgorithm | | | | Iniciar Simulação | | |----------------------------->| | | | Criar instância | | |------------------------------->| | | | | Solicitar passo (AJAX) | | |----------------------------->| | | | Chamar step() | | |------------------------------->| | | | | | Simular falhas/recuperações | | | <--------------------------->| | | | | | Gerar mensagem | | | <--------------------------->| | | | | | Broadcast mensagem | | | <--------------------------->| | | | | | Entregar mensagens | | | <--------------------------->| | | | | | Passar token | | | <--------------------------->| | | | | | Retornar estado da simulação | | |<-------------------------------| | | | | Resposta JSON com | | | estado da simulação | | |<-----------------------------| | | | | | Atualizar interface | | |----------------------------->| | | | |


Este diagrama de sequência ilustra o fluxo básico de interação entre o Cliente (navegador do usuário), o Servidor (aplicação Flask) e o algoritmo PrivilegeBasedAlgorithm durante um ciclo de simulação.

1. O Cliente inicia a simulação acessando a página.
2. O Servidor cria uma instância do PrivilegeBasedAlgorithm.
3. O Cliente solicita um passo da simulação via AJAX.
4. O Servidor chama o método `step()` do algoritmo.
5. O algoritmo executa várias etapas internas:
   - Simula falhas e recuperações de processos
   - Gera uma nova mensagem (se aplicável)
   - Realiza o broadcast da mensagem
   - Entrega mensagens aos processos ativos
   - Passa o token para o próximo processo
6. O algoritmo retorna o estado atual da simulação ao Servidor.
7. O Servidor envia a resposta JSON com o estado da simulação ao Cliente.
8. O Cliente atualiza a interface com as novas informações.

Este ciclo se repete cada vez que o Cliente solicita um novo passo da simulação.

## Descrição do Serviço no Servidor

O servidor Flask gerencia dois componentes principais:

1. **Sistema de Autenticação e Gerenciamento de Usuários**
   - Utiliza Flask-Login para gerenciamento de sessões
   - Implementa hashing de senhas com Argon2
   - Realiza validações de entrada e sanitização de dados
   - Gerencia diferentes níveis de acesso (admin, cliente, PQL)

2. **Simulador de Mensagens Distribuídas**
   - Implementa a classe `PrivilegeBasedAlgorithm`
   - Gerencia o ciclo de vida dos processos
   - Controla a circulação do token entre processos
   - Simula a geração, envio e recepção de mensagens
   - Implementa lógica de falhas e recuperações de processos

## Blocos de Código Relevantes

### Simulador de Mensagens Distribuídas

#### Classe Process (Simplificada)

```python
class Process:
    def __init__(self, process_id, total_processes):
        self.id = process_id
        self.total_processes = total_processes
        self.message_queues = [[] for _ in range(total_processes)]
        self.is_failed = False

    def generate_message(self):
        # Gera uma mensagem com 80% de chance se o processo não falhou
        if not self.is_failed and random.random() < 0.8:
            message = f"Mensagem do Processo {self.id}: {random.randint(1, 1000)}"
            global_timestamp = global_counter.next()
            return (global_timestamp, self.id, message)
        return None

    def receive_message(self, global_timestamp, sender_id, message):
        # Adiciona a mensagem recebida à fila apropriada
        self.message_queues[sender_id].append((global_timestamp, message))

    def deliver_messages(self):
        # Processa e entrega todas as mensagens nas filas
        delivered = []
        for sender_id in range(self.total_processes):
            while self.message_queues[sender_id]:
                timestamp, message = self.message_queues[sender_id].pop(0)
                delivered.append(f"Emissor {sender_id}: {message}")
        return delivered
```

### Algoritmo Baseado em Privilégio (Simplificado)
```python
class PrivilegeBasedAlgorithm:
    def __init__(self, num_processes):
        self.num_processes = num_processes
        self.token_holder = 0
        self.processes = [Process(i, num_processes) for i in range(num_processes)]

    def step(self):
        # Simula falhas e recuperações de processos
        self.simulate_failures_and_recoveries()

        # Encontra o próximo processo ativo para ser o detentor do token
        current_process = self.get_next_active_process()

        # Gera e processa mensagens
        new_message = current_process.generate_message()
        if new_message:
            self.broadcast_message(new_message)

        # Entrega mensagens para processos ativos
        delivered_messages = self.deliver_messages_to_active_processes()

        # Passa o token para o próximo processo ativo
        self.pass_token()

        return self.get_simulation_state()

    def simulate_failures_and_recoveries(self):
        # Implementação da lógica de falhas e recuperações

    def get_next_active_process(self):
        # Lógica para encontrar o próximo processo ativo

    def broadcast_message(self, message):
        # Envia a mensagem para todos os processos

    def deliver_messages_to_active_processes(self):
        # Processa mensagens em processos ativos

    def pass_token(self):
        # Passa o token para o próximo processo ativo

    def get_simulation_state(self):
        # Retorna o estado atual da simulação
```
### Rota Flask Principal para o Simulador
```python
@app.route('/step')
@login_required
def step():
    if users[current_user.id]['role'] != 'cliente':
        return jsonify({"error": "Acesso negado"}), 403
    
    global algorithm
    result = algorithm.step()
    return jsonify(result)
```
## Requisitos funcionais

### Sistema de Autenticação e Gerenciamento de Usuários

1. **Registro de Usuários**
   - O sistema deve permitir que novos usuários se registrem fornecendo nome de usuário, senha e e-mail.
   - As senhas devem ser armazenadas de forma segura utilizando o algoritmo de hash Argon2.

2. **Autenticação de Usuários**
   - Os usuários devem poder fazer login usando seu nome de usuário e senha.
   - O sistema deve validar as credenciais e criar uma sessão segura para usuários autenticados.

3. **Gerenciamento de Perfil**
   - Usuários autenticados devem poder visualizar e editar suas informações de perfil.
   - Deve ser possível alterar a senha, mantendo a segurança do armazenamento.

4. **Controle de Acesso Baseado em Papéis**
   - O sistema deve suportar diferentes níveis de acesso: admin, cliente e PQL.
   - Cada papel deve ter permissões específicas dentro do sistema.

5. **Logout**
   - Os usuários devem poder encerrar sua sessão de forma segura.

6. **Painel Administrativo**
   - Usuários com papel de admin devem ter acesso a um painel para gerenciar outros usuários.
   - Funcionalidades de CRUD (Criar, Ler, Atualizar, Deletar) para contas de usuário. 

### Simulador de Mensagens Distribuídas

7. **Inicialização da Simulação**
   - Usuários com papel de cliente devem poder iniciar uma nova simulação de sistema distribuído.
   - A simulação deve começar com um número predefinido de processos.

8. **Visualização do Estado da Simulação**
   - A interface deve exibir o estado atual de cada processo na simulação.
   - Deve mostrar qual processo detém o token atual.

9. **Geração e Transmissão de Mensagens**
   - O sistema deve simular a geração de mensagens por processos ativos.
   - As mensagens devem ser transmitidas para outros processos de acordo com o algoritmo baseado em privilégio.

10. **Simulação de Falhas e Recuperações**
    - O sistema deve simular falhas aleatórias em processos.
    - O sistema força o proceso 1 a falhar para demonstrar a ordem na fila.
    - Processos falhos devem poder se recuperar após um período.

11. **Visualização de Filas de Mensagens**
    - Para cada processo, o sistema deve exibir as filas de mensagens recebidas e não processadas.

12. **Execução Passo a Passo**
    - Os usuários devem poder avançar a simulação um passo de cada vez.
    - Cada passo deve atualizar o estado global da simulação.

13. **Histórico de Mensagens**
    - O sistema deve manter e exibir um histórico das mensagens processadas por cada processo.

14. **Interface Responsiva**
    - A interface do usuário deve se atualizar em tempo real para refletir o estado atual da simulação.

15. **Controle de Acesso ao Simulador**
    - Apenas usuários com papel de cliente devem ter acesso ao simulador de mensagens distribuídas.

18. **Feedback Visual**
    - O sistema deve fornecer feedback visual claro sobre eventos importantes, como falhas de processos ou passagem de token.
