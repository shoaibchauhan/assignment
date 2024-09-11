# FastAPI Project with MongoDB and JWT Authentication

This project is a FastAPI application that uses MongoDB with MongoEngine for data storage and JWT for authentication. It includes basic CRUD operations and role-based access control.

## Project Setup

### Prerequisites

- Python 3.8 or higher
- MongoDB instance (local or cloud)

### Installation

1. Clone the repository:
    ```bash
    git clone https://github.com/shoaibchauhan/assignment.git
    cd your-repo
    ```

2. Create a virtual environment:
    ```bash
    python -m venv venv
    ```

3. Activate the virtual environment:
    - On Windows:
        ```bash
        venv\Scripts\activate
        ```
    - On macOS/Linux:
        ```bash
        source venv/bin/activate
        ```

4. Install the required packages:
    ```bash
    pip install -r requirements.txt
    ```

### Configuration

Update the `SECRET_KEY` and `ALGORITHM` in `dependencies.py` with your own values.

### Running the Application

1. Start the Uvicorn server:
    ```bash
    uvicorn main:app --reload
    ```

2. Open your browser and go to `http://localhost:8000/docs` to view the Swagger UI documentation and interact with the API.

### API Endpoints

- **POST /register**: Create a new user. Requires `username`, `password`, and `role`.
- **POST /login**: Authenticate a user and obtain a JWT token. Requires `username`, `password`, and `role`.
- **GET /projects**: List projects created by the authenticated user.
- **POST /projects**: Create a new project. Requires authentication with admin role.
- **DELETE /projects/{project_id}**: Delete a project by ID. Requires authentication with admin role.
- **PUT /projects/{project_id}**: Update a project by ID. Requires authentication with admin role.
- **GET /projects/all**: List all projects. Requires authentication with admin role.



