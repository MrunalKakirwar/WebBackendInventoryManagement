# Inventory Management System Backend

This project is a backend implementation of an Inventory Management System using Flask. It includes RESTful APIs for user authentication, managing inventory items with CRUD operations, and logging actions in a history table. The backend also handles session-based user authentication and offers a history view with relative timestamps for each action.

## Team members

- Sarita Joshi
- Hritika Phule
- Mrunal Kakirwar
- Snehal Chavan
- Biplove Gc


## Features

- **User Authentication**: Registration, login, and logout functionalities with session-based authentication.
- **CRUD Operations for Inventory**: Create, read, update, and delete inventory items.
- **User-Specific Inventory Management**: Each user can only access and manage their own inventory items.
- **Session Management**: Uses secure session cookies to manage user sessions.
- **History Logging**: Logs each action (e.g., item created, updated, deleted) in a history table with a timestamp.
- **Error Handling & Validation**: Ensures each request is valid and provides descriptive error messages for invalid requests.

## Technologies Used

- **Flask**: Web framework for building the backend API.
- **Flask-SQLAlchemy**: SQLAlchemy extension for database management.
- **Flask-Bcrypt**: For password hashing.
- **Flask-Session**: For managing session data.

## Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/MrunalKakirwar/WebBackendInventoryManagement.git
   cd WebBackendInventoryManagement
   ```


2. **Set up a virtual environment**:
   ```bash
   python -m venv venv  
    venv\Scripts\activate.bat
   ```

3. **Install dependencies**:
    ```bash
   pip install -r requirements.txt
    ```

4. **Set up environment variables**:
    
   Create a `.env` file with the following content:  
   SECRET_KEY=your_secret_key
  

6. **Run the application**:
    ```bash
   python app.py
    ```
   The app will be accessible at `http://localhost:5000`.
   

## API Endpoints

### Authentication

- **POST /register**: Register a new user.
  - **Request**: `{ "username": "testuser", "email": "test@example.com", "password": "password123" }`
  - **Response**: `{"status": "successful", "message": "User registered successfully!"}`

- **POST /login**: Login with username and password.
  - **Request**: `{ "username": "testuser", "password": "password123" }`
  - **Response**: `{"status": "successful", "message": "Login successful!"}`

- **POST /logout**: Logout the user.
  - **Response**: `{"status": "successful", "message": "Logged out successfully!"}`

### Inventory Management (Requires Authentication)

- **POST /inventory**: Create a new inventory item.
  - **Request**: `{ "item_name": "Laptop", "description": "Dell XPS", "quantity": 5, "price": 1200.00 }`
  - **Response**: `{"status": "successful", "message": "Item created successfully!", "item_id": 1}`

- **GET /inventory**: Retrieve all inventory items for the logged-in user.
  - **Response**: A list of items with their details.

- **GET /inventory/<id>**: Retrieve a specific inventory item by ID.
  - **Response**: `{"status": "successful", "item": { "id": 1, "item_name": "Laptop", ... }}`

- **PUT /inventory/<id>**: Update a specific inventory item by ID.
  - **Request**: `{ "item_name": "Updated Laptop", "quantity": 10, "price": 1100.00 }`
  - **Response**: `{"status": "successful", "message": "Item updated successfully!"}`

- **DELETE /inventory/<id>**: Delete a specific inventory item by ID.
  - **Response**: `{"status": "successful", "message": "Item deleted successfully!"}`

### Action History

- **GET /history**: Retrieve the action history, showing the latest changes on top.
  - **Response**: A list of actions with details.

## Configuration

The app configuration is located in `config.py`.

- **SECRET_KEY**: Used to secure session data.
- **SESSION_TYPE**: Set to `'filesystem'` for development, storing session data on the server's filesystem.
- **SESSION_COOKIE_SECURE**: Set to `True` for secure cookies over HTTPS (recommended for production).
- **PERMANENT_SESSION_LIFETIME**: Controls session expiration time (e.g., 30 minutes).

## Database Schema

1. **User Table**:
   - `id`: Integer, primary key.
   - `username`: String, unique.
   - `email`: String, unique.
   - `password_hash`: String.

2. **Inventory Table**:
   - `id`: Integer, primary key.
   - `user_id`: Foreign key referencing `User`.
   - `item_name`: String.
   - `description`: String.
   - `quantity`: Integer.
   - `price`: Float.

3. **History Table**:
   - `id`: Integer, primary key.
   - `user_id`: Integer.
   - `item_id`: Integer, nullable.
   - `action_type`: String (e.g., "create", "update", "delete").
   - `timestamp`: DateTime with timezone.

## Error Handling

The API includes exception handling to manage errors gracefully. Common errors include:
- **400 Bad Request**: For validation errors, missing fields, or incorrect data types.
- **403 Unauthorized**: When a user tries to access resources without being logged in.
- **404 Not Found**: When an item is not found in the inventory.
- **500 Internal Server Error**: For unexpected server errors.

