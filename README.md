# Projeto de Autenticação, Gerenciamento de Usuários e Simulador de Mensagens Distribuídas (Baseada em privilégio)

## Descrição da Proposta do Trabalho

Este projeto combina um sistema robusto de autenticação e gerenciamento de usuários com um simulador de mensagens distribuídas baseado em privilégio. O sistema utiliza Flask como framework web e oferece uma solução segura e escalável para aplicações web que necessitam de controle de acesso baseado em privilégios, além de fornecer uma ferramenta educacional para entender sistemas distribuídos baseados em privilégio disponivel na dashboard de usuários do tipo "cliente".

### Objetivos Principais:

1. **Autenticação Segura e Gerenciamento de Usuários**
2. **Simulador de Mensagens Distribuídas**

<details>
<summary><strong>Detalhes dos Objetivos</strong></summary>

#### Autenticação Segura e Gerenciamento de Usuários:
- Implementar um sistema de login seguro com criptografia Argon2
- Permitir registro, visualização e atualização de perfis de usuários
- Implementar controle de acesso baseado em papéis
- Desenvolver uma interface administrativa para gerenciamento de usuários
- Incorporar medidas de segurança avançadas
- Criar uma interface de usuário intuitiva

#### Simulador de Mensagens Distribuídas:
- Implementar um simulador que demonstra a comunicação entre múltiplos processos em um sistema distribuído
- Utilizar um algoritmo baseado em privilégio para controlar a troca de mensagens
- Simular falhas e recuperações de processos
- Fornecer uma interface visual para acompanhar o estado do sistema distribuído

</details>

## Modelo de Dados Sistema Distribuido Baseado em Privilégio

<details>
<summary><strong>Detalhes do Modelo de Dados</strong></summary>

- **Process**: (id, status, message_queues, delivered_messages, processed_messages)
- **PrivilegeBasedAlgorithm**: (num_processes, token_holder, processes, global_message_history)

</details>

## Configuração e Instalação

<details>
<summary><strong>Passos de Instalação</strong></summary>

1. Clone o repositório
2. Crie um ambiente virtual
3. Instale as dependências:
pip install flask
pip install flask-login
pip install passlib
4. Execute o projeto:
python app.py

</details>

## Requisitos Funcionais

### Cliente (Frontend)

1. **Funcionalidades de Autenticação e Gerenciamento de Usuários**
2. **Simulador de Mensagens Distribuídas**

<details>
<summary><strong>Detalhes dos Requisitos do Cliente</strong></summary>

#### Autenticação e Gerenciamento de Usuários:
- Registro, login, logout de usuários
- Visualização e atualização de perfil
- Acesso à área administrativa (para admins)

#### Simulador de Mensagens Distribuídas:
- Iniciar a simulação com um número predefinido de processos
- Visualizar o estado atual de cada processo
- Observar a troca de mensagens entre os processos
- Acompanhar o processo que detém o token atual
- Visualizar as filas de mensagens de cada processo
- Avançar a simulação passo a passo

</details>

### Servidor (Backend)

1. **Funcionalidades de Autenticação e Gerenciamento de Usuários**
2. **Simulador de Mensagens Distribuídas**

<details>
<summary><strong>Detalhes dos Requisitos do Servidor</strong></summary>

#### Autenticação e Gerenciamento de Usuários:
- Processamento de registro, autenticação e gerenciamento de sessões
- Recuperação e atualização de dados de usuários
- Funcionalidades administrativas

#### Simulador de Mensagens Distribuídas:
- Gerenciar o estado de cada processo na simulação
- Implementar o algoritmo baseado em privilégio para troca de mensagens
- Simular falhas aleatórias e recuperação de processos
- Processar e ordenar as mensagens recebidas por cada processo
- Fornecer atualizações sobre o estado da simulação a cada passo

</details>

## Descrição do Serviço no Servidor

O servidor Flask gerencia tanto o sistema de autenticação quanto o simulador de mensagens distribuídas:

1. **Sistema de Autenticação e Gerenciamento de Usuários**
2. **Simulador de Mensagens Distribuídas**

<details>
<summary><strong>Detalhes do Serviço no Servidor</strong></summary>

#### Sistema de Autenticação e Gerenciamento de Usuários:
- Autenticação de usuários
- Gerenciamento de usuários (CRUD)
- Controle de acesso baseado em papéis
- Armazenamento seguro de dados de usuários

#### Simulador de Mensagens Distribuídas:
- Implementação do `PrivilegeBasedAlgorithm`
- Gerenciamento do ciclo de vida dos processos
- Controle da circulação do token entre processos
- Geração, envio e recepção de mensagens
- Tratamento de falhas e recuperação de processos
- Ordenação e processamento de mensagens em cada processo

</details>

## Comunicação Cliente-Servidor

A comunicação entre cliente e servidor é baseada em requisições HTTP/HTTPS:

1. **Sistema de Autenticação**
2. **Simulador de Mensagens Distribuídas**

<details>
<summary><strong>Detalhes da Comunicação</strong></summary>

#### Sistema de Autenticação:
- Utiliza requisições POST para login, registro e atualização de perfil
- Utiliza requisições GET para recuperação de dados de usuário e logout
- Implementa tokens de sessão para autenticação contínua

#### Simulador de Mensagens Distribuídas:
- O cliente inicia a simulação acessando `/distributed-messaging-simulator`
- O cliente solicita avanços na simulação através de requisições AJAX à rota `/step`
- O servidor retorna o estado atualizado da simulação em formato JSON
- O cliente atualiza a interface com as informações recebidas

</details>

### Diagrama de Sequência (Simulador)

Cliente Servidor | | |--- Iniciar Simulação --->| |<-- Página HTML Inicial --| | | |--- Requisição de Passo ->| |<-- Resposta JSON --------| | (Estado da Simulação) | | ... |


## Blocos de Código Relevantes

### Recepção e Envio de Mensagens (Simulador)

```python
class Process:
    def receive_message(self, global_timestamp, sender_id, message):
        self.message_queues[sender_id].append((global_timestamp, message))

    def generate_message(self):
        if self.is_failed:
            return None
        if random.random() < 0.8:  # 80% chance to generate a message
            message = f"Mensagem do Processo {self.id}: {random.randint(1, 1000)}"
            global_timestamp = global_counter.next()
            return (global_timestamp, self.id, message)
        return None

### Rota para Avanço da Simulação

```python
@app.route('/step')
@login_required
def step():
    if users[current_user.id]['role'] != 'cliente':
        return jsonify({"error": "Acesso negado"}), 403
    
    global algorithm
    result = algorithm.step()
    return jsonify(result)
