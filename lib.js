          async function criarJaEra() {
            // Verificação de Segurança
            if (!window.isSecureContext && window.location.hostname !== 'localhost') {
                return alert("ERRO DE SEGURANÇA:\n\nEste sistema de criptografia exige HTTPS.\nPor favor, acesse usando https:// no início do endereço.");
            }

            const text = document.getElementById('msg').value;

            const pass = document.getElementById('pass').value

            if(!text || !pass) return alert("Preencha a mensagem e a senha!");

            const enc = new TextEncoder();
            const salt = window.crypto.getRandomValues(new Uint8Array(16));
            const iv = window.crypto.getRandomValues(new Uint8Array(12));

            // Derivar chave da senha
            const keyMat = await window.crypto.subtle.importKey("raw", enc.encode(pass), {name: "PBKDF2"}, false, ["deriveKey"]);
            const key = await window.crypto.subtle.deriveKey(
                {name: "PBKDF2", salt: salt, iterations: 100000, hash: "SHA-256"},
                keyMat, {name: "AES-GCM", length: 256}, false, ["encrypt"]
            );

            // Criptografar
            const encrypted = await window.crypto.subtle.encrypt({name: "AES-GCM", iv: iv}, key, enc.encode(text));

            // Hash de autenticação (Senha + Salt Hex)
            const authHashBuf = await window.crypto.subtle.digest("SHA-256", enc.encode(pass + toHex(salt)));

            // Enviar
            const res = await fetch('BACKENDAPI', {
                method: 'POST',
                body: JSON.stringify({
                    encrypted_data: toBase64(encrypted),
                    iv: toHex(iv),
                    salt: toHex(salt),
                    auth_hash: toHex(authHashBuf)
                })
            });

            const data = await res.json();
            
            if(data.status === 'success') {
                document.getElementById('step1').classList.add('hidden');
                document.getElementById('step2').classList.remove('hidden');
                
                // URL limpa
                const link = `${window.location.origin}${window.location.pathname.replace('index.html','')}view.html?id=${data.id}`;
                document.getElementById('finalLink').innerText = link;
            
                // Formatação do número
                const formattedNumber = new Intl.NumberFormat('pt-BR').format(data.number);
                document.getElementById('thankYouMsg').innerText = `Obrigado! Você é a ${formattedNumber}ª pessoa a usar o JáEra.`;
				document.getElementById('msg').value = '';						
				document.getElementById('pass').value = '';
            } else {
                alert('Erro: ' + data.error);
            }
        }

        async function abrirJaEra() {
            const id = new URLSearchParams(window.location.search).get('id');
            const pass = document.getElementById('pass').value;
            const errBox = document.getElementById('errorMsg');
            
            // Função rápida para mostrar erro
            const showError = (msg) => {
                errBox.innerText = msg;
                errBox.style.display = 'block';
            };

            if(!id) return showError("Link inválido ou incompleto.");
            if(!pass) return showError("Por favor, digite a senha.");

            // Feedback visual de carregamento
            const btn = document.querySelector('button.destroy');
            const originalText = btn.innerHTML;
            btn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Processando...';
            btn.disabled = true;

            try {
                // 1. Handshake (Pega o Salt)
                const res1 = await fetch('BACKENDAPI2', {
                    method: 'POST',
                    body: JSON.stringify({ id: id, step: 'handshake' })
                });
                const data1 = await res1.json();
                if(data1.error) throw new Error(data1.error);

                // 2. Hash para Autenticação
                const enc = new TextEncoder();
                const authHashBuf = await window.crypto.subtle.digest("SHA-256", enc.encode(pass + data1.salt));
                
                // 3. Unlock (Pede a destruição e o conteúdo cifrado)
                const res2 = await fetch('BACKENDAPI2', {
                    method: 'POST',
                    body: JSON.stringify({ id: id, step: 'unlock', auth_hash: toHex(authHashBuf) })
                });
                const data2 = await res2.json();
                if(data2.error) throw new Error(data2.error);

                // 4. Descriptografia Local
                const keyMat = await window.crypto.subtle.importKey("raw", enc.encode(pass), {name: "PBKDF2"}, false, ["deriveKey"]);
                const key = await window.crypto.subtle.deriveKey(
                    {name: "PBKDF2", salt: fromHex(data1.salt), iterations: 100000, hash: "SHA-256"},
                    keyMat, {name: "AES-GCM", length: 256}, false, ["decrypt"]
                );

                const dec = await window.crypto.subtle.decrypt(
                    {name: "AES-GCM", iv: fromHex(data2.iv)}, key, fromBase64(data2.encrypted_data)
                );

                // Sucesso: Troca a tela
                document.getElementById('finalContent').innerText = new TextDecoder().decode(dec);
                document.getElementById('lockScreen').classList.add('hidden');
                document.getElementById('msgScreen').classList.remove('hidden');

            } catch (e) {
                btn.innerHTML = originalText;
                btn.disabled = false;
                showError(e.message || "Senha incorreta ou erro de conexão.");
            }
        }

        function toHex(buf) { return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2,'0')).join(''); }
        function toBase64(buf) { return btoa(String.fromCharCode(...new Uint8Array(buf))); }
        function fromHex(hex) { return new Uint8Array(hex.match(/.{1,2}/g).map(byte => parseInt(byte, 16))); }
        function fromBase64(str) { return Uint8Array.from(atob(str), c => c.charCodeAt(0)); }
