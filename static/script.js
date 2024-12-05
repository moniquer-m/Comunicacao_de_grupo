const NUM_PROCESSES = parseInt(document.getElementById('process-data').getAttribute('data-num-processes'));

function updateProcesses(tokenHolder, processStatus) {
    const emittersDiv = document.getElementById('emitters');
    const receiversDiv = document.getElementById('receivers');
    emittersDiv.innerHTML = '';
    receiversDiv.innerHTML = '';
    for (let i = 0; i < NUM_PROCESSES; i++) {
        const emitterDiv = document.createElement('div');
        emitterDiv.className = `process emitter ${i === tokenHolder ? 'token-holder' : ''}`;
        emitterDiv.textContent = `Emissor ${i}`;
        if (processStatus[i] === "Falhou") {
            emitterDiv.classList.add('failed');
        }
        emittersDiv.appendChild(emitterDiv);

        const receiverDiv = document.createElement('div');
        receiverDiv.className = 'process receiver';
        receiverDiv.textContent = `Receptor ${i}`;
        if (processStatus[i] === "Falhou") {
            receiverDiv.classList.add('failed');
        }
        receiversDiv.appendChild(receiverDiv);
    }
}

function displayMessage(content, type) {
    const messageDiv = document.createElement('div');
    messageDiv.className = `message ${type}`;
    messageDiv.textContent = content;
    document.getElementById('messages').prepend(messageDiv);
}

function updateReceiverQueues(queues) {
    console.log("Updating receiver queues with:", queues);
    const tbody = document.querySelector('#receiver-queues tbody');
    tbody.innerHTML = '';
    queues.forEach((queue, index) => {
        const row = tbody.insertRow();
        const cellReceiver = row.insertCell(0);
        const cellMessages = row.insertCell(1);
        cellReceiver.textContent = `Receptor ${index}`;
        
        if (Array.isArray(queue) && queue.length > 0) {
            cellMessages.textContent = queue.join(' | ');
        } else {
            cellMessages.textContent = 'Vazia';
        }
    });
}

function updateProcessedMessages(processedMessages) {
    console.log("Updating processed messages:", processedMessages);
    const tbody = document.querySelector('#processed-messages tbody');
    tbody.innerHTML = '';
    processedMessages.forEach((messages, index) => {
        const row = tbody.insertRow();
        const cellReceiver = row.insertCell(0);
        const cellMessages = row.insertCell(1);
        cellReceiver.textContent = `Receptor ${index}`;
        
        if (Array.isArray(messages) && messages.length > 0) {
            cellMessages.textContent = messages.join(' | ');
        } else {
            cellMessages.textContent = 'Nenhuma mensagem processada';
        }
    });
}

function updateDeliveredMessages(delivered) {
    console.log("Updating delivered messages:", delivered);
    const messagesDiv = document.getElementById('messages');
    delivered.forEach((processMsgs, index) => {
        processMsgs.forEach(msg => {
            const messageDiv = document.createElement('div');
            messageDiv.className = 'message message-received';
            messageDiv.textContent = `Processo ${index} entregou: ${msg}`;
            messagesDiv.prepend(messageDiv);
        });
    });
}

function updateProcessStatus(processStatus) {
    const statusContent = document.getElementById('process-status-content');
    statusContent.innerHTML = '';
    processStatus.forEach((status, i) => {
        const processDiv = document.createElement('div');
        processDiv.className = 'process-status';
        
        processDiv.textContent = `Processo ${i}: ${status}`;
        if (status === "Falhou") {
            processDiv.style.color = 'red';
        } else if (status === "Ativo") {
            processDiv.style.color = 'blue';
        } else if (status === "Recuperado") {
            processDiv.style.color = 'green';
        }
        statusContent.appendChild(processDiv);
    });
}

function step() {
    fetch('/step')
        .then(response => response.json())
        .then(data => {
            console.log("Dados completos recebidos do servidor:", data);
            updateProcesses(data.token_holder, data.process_status);
            
            if (data.sent_message) {
                displayMessage(data.sent_message, 'message-sent');
            }
            
            updateReceiverQueues(data.receiver_queues);
            updateProcessedMessages(data.processed_messages);
            updateDeliveredMessages(data.delivered_messages);
            updateProcessStatus(data.process_status);
        })
        .catch(error => {
            console.error("Erro ao buscar ou processar dados:", error);
        });
}

// Inicialização
updateProcesses(0, Array(NUM_PROCESSES).fill("Ativo"));