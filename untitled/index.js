const http = require('http');
const fs = require('fs');
const path = require('path');
const url = require('url');
const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');

// Создаем базу данных для пользователей
const db = new sqlite3.Database('users.db', (err) => {
    if (err) {
        console.error('Ошибка подключения к базе данных:', err);
    } else {
        console.log('Подключение к базе данных пользователей установлено');
    }
});

// Папка для хранения задач пользователей
const TASKS_DIR = 'tasks';

// Создаем папку для задач, если ее нет
if (!fs.existsSync(TASKS_DIR)) {
    fs.mkdirSync(TASKS_DIR);
}

// Создаем таблицу пользователей при запуске
db.serialize(() => {
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
});

// Функции для работы с задачами в JSON
function getUserTasksFile(userId) {
    return path.join(TASKS_DIR, `tasks_${userId}.json`);
}

function loadUserTasks(userId) {
    const tasksFile = getUserTasksFile(userId);
    try {
        if (fs.existsSync(tasksFile)) {
            return JSON.parse(fs.readFileSync(tasksFile, 'utf8'));
        }
    } catch (error) {
        console.error('Ошибка загрузки задач пользователя', userId, ':', error);
    }
    return [];
}

function saveUserTasks(userId, tasks) {
    const tasksFile = getUserTasksFile(userId);
    try {
        fs.writeFileSync(tasksFile, JSON.stringify(tasks, null, 2));
        console.log('Задачи сохранены для пользователя:', userId);
    } catch (error) {
        console.error('Ошибка сохранения задач пользователя', userId, ':', error);
    }
}

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
                user: {
                    id: user.id,
                    username: user.username
                }
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
                [parseInt(userId), username],
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
    try {
        const tasks = loadUserTasks(userId);
        console.log('Загружено задач для пользователя', userId, ':', tasks.length);
        sendResponse(res, 200, tasks);
    } catch (error) {
        console.error('Ошибка получения задач:', error);
        sendResponse(res, 500, { error: 'Ошибка сервера' });
    }
}

// Создание задачи
async function createTask(req, res, body, userId) {
    try {
        const { text, priority, category, deadline } = body;

        console.log('Создание задачи для пользователя:', userId);
        console.log('Данные задачи:', { text, priority, category, deadline });

        if (!text || text.trim() === '') {
            sendResponse(res, 400, { error: 'Текст задачи обязателен' });
            return;
        }

        const tasks = loadUserTasks(userId);
        const newTask = {
            id: `task_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
            text: text.trim(),
            priority: priority || 'medium',
            category: category || 'personal',
            deadline: deadline || null,
            completed: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString()
        };

        tasks.push(newTask);
        saveUserTasks(userId, tasks);

        console.log('Задача создана с ID:', newTask.id);
        sendResponse(res, 201, {
            id: newTask.id,
            message: 'Задача успешно создана',
            task: newTask
        });
    } catch (error) {
        console.error('Ошибка создания задачи:', error);
        sendResponse(res, 500, { error: 'Ошибка сервера' });
    }
}

// Обновление задачи
async function updateTask(req, res, body, userId, taskId) {
    try {
        const tasks = loadUserTasks(userId);
        const taskIndex = tasks.findIndex(t => t.id === taskId);

        if (taskIndex === -1) {
            sendResponse(res, 404, { error: 'Задача не найдена' });
            return;
        }

        const updatedTask = {
            ...tasks[taskIndex],
            ...body,
            updated_at: new Date().toISOString()
        };

        // Конвертируем completed в boolean если нужно
        if (body.completed !== undefined) {
            updatedTask.completed = Boolean(body.completed);
        }

        tasks[taskIndex] = updatedTask;
        saveUserTasks(userId, tasks);

        sendResponse(res, 200, { message: 'Задача обновлена' });
    } catch (error) {
        console.error('Ошибка обновления задачи:', error);
        sendResponse(res, 500, { error: 'Ошибка сервера' });
    }
}

// Удаление задачи
async function deleteTask(req, res, userId, taskId) {
    try {
        const tasks = loadUserTasks(userId);
        const filteredTasks = tasks.filter(t => t.id !== taskId);

        if (tasks.length === filteredTasks.length) {
            sendResponse(res, 404, { error: 'Задача не найдена' });
            return;
        }

        saveUserTasks(userId, filteredTasks);
        sendResponse(res, 200, { message: 'Задача удалена' });
    } catch (error) {
        console.error('Ошибка удаления задачи:', error);
        sendResponse(res, 500, { error: 'Ошибка сервера' });
    }
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
    console.log('Пользователи: SQLite database (users.db)');
    console.log('Задачи: JSON файлы в папке tasks/');
});