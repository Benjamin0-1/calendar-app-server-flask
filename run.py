from app import create_app

app = create_app()

if __name__ == '__main__':
    #app.drop_all()
    app.run(debug=True)
    