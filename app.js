document.addEventListener('DOMContentLoaded', function() {
    // Smooth scrolling for anchor links
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function(e) {
            e.preventDefault();
            const targetId = this.getAttribute('href');
            if (targetId === '#') return;
            
            const targetElement = document.querySelector(targetId);
            if (targetElement) {
                window.scrollTo({
                    top: targetElement.offsetTop - 80,
                    behavior: 'smooth'
                });
            }
        });
    });

    // Add active class to nav links on scroll
    const sections = document.querySelectorAll('section');
    const navLinks = document.querySelectorAll('.nav-links a');

    function highlightNav() {
        let current = '';
        sections.forEach(section => {
            const sectionTop = section.offsetTop;
            const sectionHeight = section.clientHeight;
            if (pageYOffset >= sectionTop - 100) {
                current = '#' + section.getAttribute('id');
            }
        });

        navLinks.forEach(link => {
            link.classList.remove('active');
            if (link.getAttribute('href') === current) {
                link.classList.add('active');
            }
        });
    }


    // Chat simulation
    const chatMessages = document.querySelector('.chat-messages');
    const messageInput = document.querySelector('.chat-input input');
    const sendButton = document.querySelector('.chat-input button');

    function addMessage(text, isReceived = true) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${isReceived ? 'received' : 'sent'}`;
        
        if (isReceived) {
            messageDiv.innerHTML = `
                <div class="message-avatar"></div>
                <div class="message-content">
                    <p>${text}</p>
                    <span class="message-time">${getCurrentTime()}</span>
                </div>`;
        } else {
            messageDiv.innerHTML = `
                <div class="message-content">
                    <p>${text}</p>
                    <span class="message-time">${getCurrentTime()}</span>
                </div>`;
        }
        
        chatMessages.appendChild(messageDiv);
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }

    function getCurrentTime() {
        const now = new Date();
        return now.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    // Send message on button click
    sendButton.addEventListener('click', () => {
        const message = messageInput.value.trim();
        if (message) {
            addMessage(message, false);
            messageInput.value = '';
            
            // Simulate response after a short delay
            setTimeout(() => {
                const responses = [
                    "That's interesting! Tell me more.",
                    "I see what you mean!",
                    "Thanks for sharing!",
                    "How can I help you with that?",
                    "That's great to hear!"
                ];
                const randomResponse = responses[Math.floor(Math.random() * responses.length)];
                addMessage(randomResponse, true);
            }, 1000);
        }
    });

    // Send message on Enter key
    messageInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') {
            sendButton.click();
        }
    });

    // Add some initial messages
    setTimeout(() => {
        addMessage("Welcome to Bawi! 👋", true);
        addMessage("Start a conversation by typing a message below.", true);
    }, 500);

    // Animate features on scroll
    const featureCards = document.querySelectorAll('.feature-card');
    
    function checkScroll() {
        featureCards.forEach(card => {
            const cardTop = card.getBoundingClientRect().top;
            const windowHeight = window.innerHeight;
            
            if (cardTop < windowHeight - 100) {
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }
        });
    }

    // Initial check
    checkScroll();
    
    // Check on scroll
    window.addEventListener('scroll', checkScroll);

    // Add hover effect to buttons
    const buttons = document.querySelectorAll('button, .btn-login, .btn-signup');
    buttons.forEach(button => {
        button.addEventListener('mouseenter', () => {
            button.style.transform = 'translateY(-2px)';
        });
        button.addEventListener('mouseleave', () => {
            button.style.transform = 'translateY(0)';
        });
    });
});

// Add parallax effect to shapes
const shapes = document.querySelectorAll('.shape');

function moveShapes(e) {
    shapes.forEach(shape => {
        const speed = shape.getAttribute('data-speed') || 10;
        const x = (window.innerWidth - e.pageX * speed) / 100;
        const y = (window.innerHeight - e.pageY * speed) / 100;
        shape.style.transform = `translate(${x}px, ${y}px)`;
    });
}

document.addEventListener('mousemove', moveShapes);
