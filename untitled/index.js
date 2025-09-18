const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// Создаем базу данных (файл todos.db появится автоматически)
const db = new sqlite3.Database('todos.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err);
    } else {
        console.log('Подключение к базе данных установлено');
    }
});

// Добавьте эту функцию после создания таблиц
function checkTableStructure() {
    console.log('Проверяем структуру таблицы tasks...');
    db.all("PRAGMA table_info(tasks)", (err, rows) => {
        if (err) {
            console.error('Ошибка при проверке структуры таблицы:', err);
            return;
        }
        console.log('Структура таблицы tasks:');
        rows.forEach(row => {
            console.log(`- ${row.name}: ${row.type} ${row.notnull ? 'NOT NULL' : ''} ${row.dflt_value ? `DEFAULT ${row.dflt_value}` : ''}`);
        });
    });
}

// Создаем таблицы при запуске
db.serialize(() => {
    // Таблица пользователей
    db.run(`CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )`, (err) => {
        if (err) console.error('Ошибка создания таблицы users:', err);
        else console.log('Таблица users готова');
    });

    // Таблица задач
    db.run(`CREATE TABLE IF NOT EXISTS tasks (
        id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        text TEXT NOT NULL,
        completed INTEGER DEFAULT 0,
        priority TEXT DEFAULT 'medium',
        category TEXT DEFAULT 'personal',
        deadline TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
    )`, (err) => {
        if (err) console.error('Ошибка создания таблицы tasks:', err);
        else console.log('Таблица tasks готова');
        checkTableStructure();
    });

    // Удаляем старую таблицу если она существует с неправильной структурой
    db.run('DROP TABLE IF EXISTS old_tasks');

    // Индексы для быстрого поиска
    db.run('CREATE INDEX IF NOT EXISTS idx_user_id ON tasks(user_id)');
    db.run('CREATE INDEX IF NOT EXISTS idx_deadline ON tasks(deadline)');
});

const server = http.createServer(async (req, res) => {
    // Настройки CORS для всех ответов
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

    // Обработка preflight запросов
    if (req.method === 'OPTIONS') {
        res.writeHead(200);
        res.end();
        return;
    }

    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    // API маршруты
    if (pathname.startsWith('/api/')) {
        await handleApiRequest(req, res, pathname);
        return;
    }

    // Статические файлы
    handleStaticFiles(req, res);
});

// Обработка API запросов
async function handleApiRequest(req, res, pathname) {
    try {
        const body = await getRequestBody(req);

        if (pathname === '/api/register' && req.method === 'POST') {
            await handleRegister(req, res, body);
        }
        else if (pathname === '/api/login' && req.method === 'POST') {
            await handleLogin(req, res, body);
        }
        else if (pathname === '/api/tasks') {
            const auth = await authenticate(req);
            if (!auth) {
                sendResponse(res, 401, { error: 'Не авторизован' });
                return;
            }

            if (req.method === 'GET') {
                await getTasks(req, res, auth.userId);
            }
            else if (req.method === 'POST') {
                await createTask(req, res, body, auth.userId);
            }
        }
        else if (pathname.startsWith('/api/tasks/')) {
            const auth = await authenticate(req);
            if (!auth) {
                sendResponse(res, 401, { error: 'Не авторизован' });
                return;
            }

            const taskId = pathname.split('/')[3];

            if (req.method === 'PUT') {
                await updateTask(req, res, body, auth.userId, taskId);
            }
            else if (req.method === 'DELETE') {
                await deleteTask(req, res, auth.userId, taskId);
            }
        }
        else {
            sendResponse(res, 404, { error: 'Не найдено' });
        }
    } catch (error) {
        console.error('Ошибка API:', error);
        sendResponse(res, 500, { error: 'Ошибка сервера' });
    }
}

// Регистрация пользователя
async function handleRegister(req, res, body) {
    const { username, email, password } = body;

    if (!username || !email || !password) {
        sendResponse(res, 400, { error: 'Все поля обязательны' });
        return;
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        db.run(
            'INSERT INTO users (username, email, password) VALUES (?, ?, ?)',
            [username, email, hashedPassword],
            function(err) {
                if (err) {
                    sendResponse(res, 400, { error: 'Пользователь уже существует' });
                    return;
                }
                sendResponse(res, 201, { message: 'Пользователь создан успешно' });
            }
        );
    } catch (error) {
        sendResponse(res, 500, { error: 'Ошибка сервера' });
    }
}

// Авторизация пользователя
async function handleLogin(req, res, body) {
    const { username, password } = body;

    console.log('Запрос на вход:', { username });

    if (!username || !password) {
        console.log('Не хватает данных');
        sendResponse(res, 400, { error: 'Логин и пароль обязательны' });
        return;
    }

    db.get(
        'SELECT * FROM users WHERE username = ?',
        [username],
        async (err, user) => {
            if (err) {
                console.log('Ошибка БД:', err.message);
                sendResponse(res, 400, { error: 'Неверные данные' });
                return;
            }

            if (!user) {
                console.log('Пользователь не найден:', username);
                sendResponse(res, 400, { error: 'Неверные данные' });
                return;
            }

            console.log('Пользователь найден:', user.id);

            const validPassword = await bcrypt.compare(password, user.password);
            if (!validPassword) {
                console.log('Неверный пароль');
                sendResponse(res, 400, { error: 'Неверные данные' });
                return;
            }

            const token = Buffer.from(`${user.id}:${username}`).toString('base64');
            console.log('Токен создан для пользователя:', user.id);

            sendResponse(res, 200, {
                token,
                user: { id: user.id, username: user.username }
            });
        }
    );
}

// Проверка авторизации
async function authenticate(req) {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Basic ')) {
        return null;
    }

    const token = authHeader.slice(6);
    try {
        const decoded = Buffer.from(token, 'base64').toString('utf-8');
        const [userId, username] = decoded.split(':');

        return new Promise((resolve) => {
            db.get(
                'SELECT id FROM users WHERE id = ? AND username = ?',
                [userId, username],
                (err, user) => {
                    if (err || !user) {
                        resolve(null);
                    } else {
                        resolve({ userId: user.id, username });
                    }
                }
            );
        });
    } catch (error) {
        return null;
    }
}

// Получение задач
async function getTasks(req, res, userId) {
    db.all(
        'SELECT * FROM tasks WHERE user_id = ? ORDER BY created_at DESC',
        [userId],
        (err, tasks) => {
            if (err) {
                console.error('Ошибка получения задач:', err);
                sendResponse(res, 500, { error: 'Ошибка базы данных' });
                return;
            }
            // Конвертируем completed из INTEGER в boolean для клиента
            const formattedTasks = tasks.map(task => ({
                ...task,
                completed: Boolean(task.completed)
            }));
            sendResponse(res, 200, formattedTasks);
        }
    );
}

// Функция для безопасного преобразования данных
function sanitizeTaskData(data) {
    return {
        text: String(data.text || '').trim(),
        priority: ['low', 'medium', 'high'].includes(String(data.priority))
            ? String(data.priority)
            : 'medium',
        category: ['personal', 'work', 'shopping', 'health'].includes(String(data.category))
            ? String(data.category)
            : 'personal',
        deadline: data.deadline ? new Date(data.deadline).toISOString().split('T')[0] : null
    };
}

async function createTask(req, res, body, userId) {
    try {
        console.log('Создание задачи для пользователя:', userId);
        console.log('Исходные данные задачи:', body);

        // Вручную преобразуем все данные к правильным типам
        const taskData = {
            text: String(body.text || '').trim(),
            priority: String(body.priority || 'medium'),
            category: String(body.category || 'personal'),
            deadline: body.deadline ? String(body.deadline) : null
        };

        console.log('Преобразованные данные задачи:', taskData);

        // Проверяем обязательные поля
        if (!taskData.text) {
            sendResponse(res, 400, { error: 'Текст задачи обязателен' });
            return;
        }

        // Проверяем допустимые значения
        const validPriorities = ['low', 'medium', 'high'];
        if (!validPriorities.includes(taskData.priority)) {
            taskData.priority = 'medium';
        }

        const validCategories = ['personal', 'work', 'shopping', 'health'];
        if (!validCategories.includes(taskData.category)) {
            taskData.category = 'personal';
        }

        // Проверяем формат даты (YYYY-MM-DD)
        if (taskData.deadline) {
            const dateRegex = /^\d{4}-\d{2}-\d{2}$/;
            if (!dateRegex.test(taskData.deadline)) {
                taskData.deadline = null;
            }
        }

        console.log('Проверенные данные задачи:', taskData);

        // Генерация ID
        const timestamp = Date.now();
        const random = Math.random().toString(36).substr(2, 9);
        const taskId = `task_${timestamp}_${random}`;

        console.log('Параметры для SQL запроса:', [
            taskId,
            userId,
            taskData.text,
            taskData.priority,
            taskData.category,
            taskData.deadline
        ]);

        // Выполняем SQL запрос с явным указанием типов
        db.run(
            'INSERT INTO tasks (id, user_id, text, priority, category, deadline) VALUES (?, ?, ?, ?, ?, ?)',
            [
                taskId,
                parseInt(userId), // Явно преобразуем в число
                taskData.text,
                taskData.priority,
                taskData.category,
                taskData.deadline
            ],
            function(err) {
                if (err) {
                    console.error('Полная ошибка базы данных:', err);
                    console.error('Детали ошибки:', {
                        errno: err.errno,
                        code: err.code,
                        message: err.message
                    });

                    // Пробуем альтернативный запрос без deadline
                    if (err.code === 'SQLITE_MISMATCH') {
                        console.log('Пробуем альтернативный запрос без deadline...');
                        db.run(
                            'INSERT INTO tasks (id, user_id, text, priority, category) VALUES (?, ?, ?, ?, ?)',
                            [
                                taskId,
                                parseInt(userId),
                                taskData.text,
                                taskData.priority,
                                taskData.category
                            ],
                            function(err2) {
                                if (err2) {
                                    console.error('Ошибка в альтернативном запросе:', err2);
                                    sendResponse(res, 500, { error: 'Ошибка при создании задачи' });
                                } else {
                                    console.log('Задача создана без deadline с ID:', taskId);
                                    sendResponse(res, 201, {
                                        id: taskId,
                                        message: 'Задача успешно создана'
                                    });
                                }
                            }
                        );
                    } else {
                        sendResponse(res, 500, { error: 'Ошибка при создании задачи' });
                    }
                    return;
                }
                console.log('Задача создана с ID:', taskId);
                sendResponse(res, 201, {
                    id: taskId,
                    message: 'Задача успешно создана'
                });
            }
        );

    } catch (error) {
        console.error('Неожиданная ошибка при создании задачи:', error);
        sendResponse(res, 500, { error: 'Внутренняя ошибка сервера' });
    }
}

// Обновление задачи
async function updateTask(req, res, body, userId, taskId) {
    try {
        // Санитизация данных
        const sanitizedData = sanitizeTaskData(body);
        const completedInt = body.completed ? 1 : 0;

        db.run(
            `UPDATE tasks 
             SET text = ?, completed = ?, priority = ?, category = ?, deadline = ?, updated_at = CURRENT_TIMESTAMP 
             WHERE id = ? AND user_id = ?`,
            [
                sanitizedData.text,
                completedInt,
                sanitizedData.priority,
                sanitizedData.category,
                sanitizedData.deadline,
                taskId,
                userId
            ],
            function(err) {
                if (err) {
                    console.error('Ошибка обновления задачи:', err);
                    sendResponse(res, 500, { error: 'Ошибка базы данных' });
                    return;
                }
                if (this.changes === 0) {
                    sendResponse(res, 404, { error: 'Задача не найдена' });
                    return;
                }
                sendResponse(res, 200, { message: 'Задача обновлена' });
            }
        );
    } catch (error) {
        console.error('Ошибка при обновлении задачи:', error);
        sendResponse(res, 500, { error: 'Внутренняя ошибка сервера' });
    }
}

// Удаление задачи
async function deleteTask(req, res, userId, taskId) {
    db.run(
        'DELETE FROM tasks WHERE id = ? AND user_id = ?',
        [taskId, userId],
        function(err) {
            if (err) {
                console.error('Ошибка удаления задачи:', err);
                sendResponse(res, 500, { error: 'Ошибка базы данных' });
                return;
            }
            if (this.changes === 0) {
                sendResponse(res, 404, { error: 'Задача не найдена' });
                return;
            }
            sendResponse(res, 200, { message: 'Задача удалена' });
        }
    );
}

// Вспомогательные функции
function getRequestBody(req) {
    return new Promise((resolve) => {
        let body = '';
        req.on('data', chunk => {
            body += chunk.toString();
        });
        req.on('end', () => {
            try {
                resolve(body ? JSON.parse(body) : {});
            } catch {
                resolve({});
            }
        });
    });
}

function sendResponse(res, statusCode, data) {
    res.writeHead(statusCode, { 'Content-Type': 'application/json' });
    res.end(JSON.stringify(data));
}

function handleStaticFiles(req, res) {
    const parsedUrl = url.parse(req.url, true);
    const pathname = parsedUrl.pathname;

    // API запросы обрабатываем отдельно
    if (pathname.startsWith('/api/')) {
        handleApiRequest(req, res, pathname);
        return;
    }

    // Корень -> регистрация
    if (pathname === '/') {
        serveFile(res, 'pages/reg.html');
        return;
    }

    // Главная страница
    if (pathname === '/index.html' || pathname === '/main.html' || pathname === '/tasks') {
        serveFile(res, 'pages/index.html');
        return;
    }

    // CSS файлы
    if (pathname.startsWith('/style/')) {
        serveFile(res, '.' + pathname, 'text/css');
        return;
    }

    // HTML страницы
    if (pathname.endsWith('.html') ||
        ['/log', '/reg', '/pravila', '/plata'].includes(pathname)) {

        let filePath = 'pages' + pathname;
        if (!filePath.endsWith('.html')) {
            filePath += '.html';
        }

        serveFile(res, filePath);
        return;
    }

    // Всё остальное - 404
    serveFile(res, 'pages/404.html');
}

function serveFile(res, filePath, contentType = null) {
    if (!contentType) {
        const extname = path.extname(filePath);
        switch (extname) {
            case '.css': contentType = 'text/css'; break;
            case '.js': contentType = 'text/javascript'; break;
            case '.json': contentType = 'application/json'; break;
            default: contentType = 'text/html';
        }
    }

    fs.readFile(filePath, (err, content) => {
        if (err) {
            res.writeHead(404);
            res.end('File not found');
        } else {
            res.writeHead(200, { 'Content-Type': contentType });
            res.end(content, 'utf-8');
        }
    });
}

const PORT = 3000;
const HOST = 'localhost';

server.listen(PORT, HOST, () => {
    console.log(`Сервер запущен: http://${HOST}:${PORT}`);
    console.log('База данных: todos.db');
});