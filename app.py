from flask import Flask, render_template, jsonify, url_for
import random

app = Flask(__name__, static_folder='static', static_url_path='/static')

NUM_PROCESSES = 5

class GlobalCounter:
    def __init__(self):
        self.count = 0

    def next(self):
        self.count += 1
        return self.count

class Process:
    def __init__(self, process_id, total_processes):
        self.id = process_id
        self.total_processes = total_processes
        self.message_queues = [[] for _ in range(total_processes)]
        self.delivered_messages = []
        self.processed_messages = []
        self.is_failed = False
        self.failure_duration = 0
        self.recovery_needed = False

    def fail(self, duration=None):
        self.is_failed = True
        self.failure_duration = duration if duration is not None else random.randint(1, 5)
        self.recovery_needed = True

    def recover(self):
        self.is_failed = False
        self.failure_duration = 0
        self.recovery_needed = True

    def generate_message(self):
        if self.is_failed:
            return None
        if random.random() < 0.8:  # 80% chance to generate a message
            message = f"Mensagem do Processo {self.id}: {random.randint(1, 1000)}"
            global_timestamp = global_counter.next()
            return (global_timestamp, self.id, message)
        return None

    def receive_message(self, global_timestamp, sender_id, message):
        self.message_queues[sender_id].append((global_timestamp, message))

    def deliver_messages(self):
        if self.is_failed:
            return []
        delivered = []
        for sender_id in range(self.total_processes):
            while self.message_queues[sender_id]:
                timestamp, message = self.message_queues[sender_id].pop(0)
                delivered_message = f"Emissor {sender_id}: {message}"
                self.delivered_messages.append(delivered_message)
                self.processed_messages.append(delivered_message)
                delivered.append(delivered_message)
        self.recovery_needed = False
        return delivered

    def get_queue_content(self):
        return [f"Emissor {sender_id}: {message}" for sender_id in range(self.total_processes) for _, message in self.message_queues[sender_id]]

    def get_processed_messages(self):
        return self.processed_messages

class PrivilegeBasedAlgorithm:
    def __init__(self, num_processes):
        self.num_processes = num_processes
        self.token_holder = 0
        self.processes = [Process(i, num_processes) for i in range(num_processes)]
        self.global_message_history = []
        self.failure_probability = 0.05  # 5% de chance de falha a cada passo
        self.forced_failure_process = 1  # Processo 1 será forçado a falhar
        self.forced_failure_duration = 2 * num_processes  # Duração da falha forçada (2 rodadas completas)
        self.current_step = 0

    def get_process_status(self):
        return ["Falhou" if process.is_failed else "Ativo" for process in self.processes]
    
    def step(self):
        self.current_step += 1
        failed_processes = []
        recovered_processes = []

        # Forçar falha no processo específico
        if self.current_step == 1:
            self.processes[self.forced_failure_process].fail(self.forced_failure_duration)
            failed_processes.append(self.forced_failure_process)

        for process in self.processes:
            if process.is_failed:
                process.failure_duration -= 1
                if process.failure_duration <= 0:
                    process.recover()
                    recovered_processes.append(process.id)
            elif process.id != self.forced_failure_process and random.random() < self.failure_probability:
                process.fail()
                failed_processes.append(process.id)

        current_process = self.processes[self.token_holder]
        
        while current_process.is_failed:
            self.token_holder = (self.token_holder + 1) % self.num_processes
            current_process = self.processes[self.token_holder]

        new_message = current_process.generate_message()
        message_generated = False
        sent_message = ""

        if new_message:
            self.global_message_history.append(new_message)
            message_generated = True
            sent_message = f"Emissor {new_message[1]}: {new_message[2]}"
            for process in self.processes:
                process.receive_message(*new_message)
        else:
            sent_message = f"Emissor {self.token_holder} não gerou mensagem"

        delivered_messages = []
        for process in self.processes:
            if not process.is_failed:
                delivered = process.deliver_messages()
                delivered_messages.append(delivered)

        receiver_queues = [process.get_queue_content() for process in self.processes]
        processed_messages = [process.get_processed_messages() for process in self.processes]

        self.token_holder = (self.token_holder + 1) % self.num_processes
        while self.processes[self.token_holder].is_failed:
            self.token_holder = (self.token_holder + 1) % self.num_processes

        result = {
            "token_holder": self.token_holder,
            "sent_message": sent_message,
            "receiver_queues": receiver_queues,
            "delivered_messages": delivered_messages,
            "processed_messages": processed_messages,
            "message_generated": message_generated,
            "failed_processes": failed_processes,
            "recovered_processes": recovered_processes,
            "process_status": self.get_process_status()
        }

        return result

global_counter = GlobalCounter()
algorithm = None

@app.route('/')
def index():
    global algorithm, global_counter
    algorithm = PrivilegeBasedAlgorithm(num_processes=NUM_PROCESSES)
    global_counter = GlobalCounter()
    return render_template('distributed-messaging-simulator.html', num_processes=NUM_PROCESSES)

@app.route('/step')
def step():
    global algorithm
    result = algorithm.step()
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True)