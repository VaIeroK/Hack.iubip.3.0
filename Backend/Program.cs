using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.IO;
using System.Linq;
using System.Net;
using System.Reflection.PortableExecutable;
using System.Text;
using System.Threading.Tasks;
using Backend;
using Dapper;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using static System.Net.Mime.MediaTypeNames;

namespace Backend
{
    class Program
    {
        static void Main(string[] args)
        {
            while (true)
            {
                try
                {
                    StartServer(args);
                }
                catch (Exception ex)
                {
                    Console.WriteLine(ex.Message);
                }
            }
        }

        static void StartServer(string[] args)
        {
            string JwtSecretKey = args[0];
            string JwtIssuer = args[1];
            string JwtAudience = args[2];
            string DbStringKey = args[3];

            byte[] DbKey = Encoding.UTF8.GetBytes(DbStringKey);
            byte[] DbIv = Encoding.UTF8.GetBytes(DbStringKey);

            var connection = DB.CreateDB("database.db");
            User.ConstructTable(connection);

            Blockchain blockchain = new Blockchain();

            // Получаем всех пользователей
            IEnumerable<User> allUsers;
            User.GetAllUsers(connection, out allUsers, DbKey, DbIv);
                
            // Создаем локальный сервер
            var listener = new HttpListener();
            listener.Prefixes.Add("http://localhost:8080/");
            listener.Start();
            Console.WriteLine("Listening on http://localhost:8080/");

            while (true)
            {
                var context = listener.GetContext();
                var request = context.Request;
                var response = context.Response;

                // Выполняем POST запрос
                var path = request.Url.LocalPath;

                // Добавление заголовков CORS
                response.AddHeader("Access-Control-Allow-Origin", "*");
                response.AddHeader("Access-Control-Allow-Credentials", "true");
                response.AddHeader("Access-Control-Allow-Methods", "*");
                response.AddHeader("Access-Control-Allow-Headers", "*");
                response.AddHeader("Access-Control-Max-Age", "1728000");

                if (request.HttpMethod == "OPTIONS")
                    response.StatusCode = 200; // Created
                else if (request.HttpMethod == "POST")
                {
                    if (path == "/login")
                    {
                        var requestBody = new byte[request.ContentLength64];
                        request.InputStream.Read(requestBody, 0, requestBody.Length);
                        var newUser = JsonConvert.DeserializeObject<LoginData>(Encoding.UTF8.GetString(requestBody));
                        User logined_user = User.LoginUser(blockchain, allUsers.ToList(), newUser.Email, newUser.Password);
                        for (int i = 0; i < request.Headers.Count; i++)
                            Console.WriteLine("header " + request.Headers.Get(i));
                        Console.WriteLine("user login " + newUser.Email + " password " + newUser.Password);
                        if (logined_user == null)
                            Console.WriteLine("user not found");

                        if (logined_user != null )
                        {
                            if (!logined_user.CheckHash())
                            {
                                var LoginData = new { Message = "Аккаунт был взломан." };
                                byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                                // Устанавливаем заголовки ответа
                                response.ContentLength64 = buffer.Length;
                                response.ContentType = "application/json";

                                response.StatusCode = 401;

                                // Возвращаем данные клиенту
                                Stream output = response.OutputStream;
                                output.Write(buffer, 0, buffer.Length);
                                output.Close();
                            }
                            else
                            {
                                var jwtService = new JwtService(JwtSecretKey, JwtIssuer, JwtAudience);
                                var access_token = jwtService.GenerateToken(logined_user.Id - 1, 1440);
                                var refresh_token = jwtService.GenerateToken(logined_user.Id - 1, 5);
                                connection.Execute($"UPDATE Users SET Token='{refresh_token}' WHERE Token='{logined_user.Token}'");
                                logined_user.Token = refresh_token;
                                var LoginData = new { AccessToken = access_token, RefreshToken = refresh_token, FirstName = logined_user.FirstName, LastName = logined_user.LastName, Surname = logined_user.Surname, Email = logined_user.Email, PhoneNumber = logined_user.PhoneNumber };
                                byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                                // Устанавливаем заголовки ответа
                                response.ContentLength64 = buffer.Length;
                                response.ContentType = "application/json";

                                response.StatusCode = 200; // Created

                                // Возвращаем данные клиенту
                                Stream output = response.OutputStream;
                                output.Write(buffer, 0, buffer.Length);
                                output.Close();
                            }
                        }
                        else
                        {
                            var LoginData = new { Message = "Неверный логин или пароль." };
                            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                            // Устанавливаем заголовки ответа
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "application/json";

                            response.StatusCode = 401;

                            // Возвращаем данные клиенту
                            Stream output = response.OutputStream;
                            output.Write(buffer, 0, buffer.Length);
                            output.Close();
                        }
                    }
                    else if (path == "/register")
                    {
                        var requestBody = new byte[request.ContentLength64];
                        request.InputStream.Read(requestBody, 0, requestBody.Length);
                        var newUser = JsonConvert.DeserializeObject<RegisterData>(Encoding.UTF8.GetString(requestBody));

                        bool ValidPass = (newUser.Password != null ? newUser.Password.Length != 0 : false);
                        Console.WriteLine($"Register user {newUser.FirstName}, email {newUser.Email}, password {newUser.Password}");
                        if (allUsers.FirstOrDefault(p => p.Email == newUser.Email) != null || !ValidPass)
                        {
                            Console.WriteLine("Register not valid");
                            var LoginData = new { Message = ValidPass ? "Пользователь уже зарегистрирован." : "Отсутствует пароль." };
                            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                            // Устанавливаем заголовки ответа
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "application/json";

                            response.StatusCode = 400;

                            // Возвращаем данные клиенту
                            Stream output = response.OutputStream;
                            output.Write(buffer, 0, buffer.Length);
                            output.Close();
                        }
                        else
                        {
                            Console.WriteLine("Register valid");
                            User NewUser = new User(newUser);
                            NewUser.Encrypt(DbKey, DbIv);
                            User.InsertUser(connection, NewUser, DbKey, DbIv);
                            NewUser.Decrypt(DbKey, DbIv);
                            blockchain.AddBlock(new BlockchainUser(newUser.Email, newUser.Password));
                            User.GetAllUsers(connection, out allUsers, DbKey, DbIv);

                            User logined_user = User.LoginUser(blockchain, allUsers.ToList(), NewUser.Email, newUser.Password);

                            var jwtService = new JwtService(JwtSecretKey, JwtIssuer, JwtAudience);
                            var access_token = jwtService.GenerateToken(logined_user.Id - 1, 1440);
                            var refresh_token = jwtService.GenerateToken(logined_user.Id - 1, 5);
                            logined_user.Token = access_token;
                            connection.Execute($"UPDATE Users SET Token='{logined_user.Token}' WHERE Id=(SELECT max(Id) FROM Users)");
                            Console.WriteLine("Call Register, access token: " + access_token);
                            Console.WriteLine("Call Register, refresh token: " + logined_user.Token);
                            var LoginData = new { AccessToken = access_token, RefreshToken = refresh_token, FirstName = logined_user.FirstName, LastName = logined_user.LastName, Surname = logined_user.Surname, Email = logined_user.Email, PhoneNumber = logined_user.PhoneNumber };
                            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                            // Устанавливаем заголовки ответа
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "application/json";

                            response.StatusCode = 201; // Created

                            // Возвращаем данные клиенту
                            Stream output = response.OutputStream;
                            output.Write(buffer, 0, buffer.Length);
                            output.Close();
                        }
                    }
                    else if (path == "/refresh")
                    {
                        string token = "";
                        for (int i = 0; i < request.Headers.Count; i++)
                        {
                            string header = request.Headers.Get(i);
                            if (header.Contains("Bearer "))
                            {
                                token = header.Substring(header.IndexOf(" ") + 1);
                                break;
                            }
                        }

                        List<User> TempUser = connection.Query<User>($"SELECT * FROM Users WHERE Token='{token}'").ToList();
                        if (TempUser.Count() > 0)
                        {
                            var jwtService = new JwtService(JwtSecretKey, JwtIssuer, JwtAudience);
                            var access_token = jwtService.GenerateToken(TempUser[0].Id - 1, 1440);
                            var refresh_token = jwtService.GenerateToken(TempUser[0].Id - 1, 5);
                            TempUser[0].Token = refresh_token;
                            connection.Execute($"UPDATE Users SET Token='{TempUser[0].Token}' WHERE Token='{token}'");

                            var LoginData = new { AccessToken = access_token, RefreshToken = refresh_token };
                            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                            // Устанавливаем заголовки ответа
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "application/json";

                            response.StatusCode = 200; // Created

                            // Возвращаем данные клиенту
                            Stream output = response.OutputStream;
                            output.Write(buffer, 0, buffer.Length);
                            output.Close();
                            response.Close();
                            continue;
                        }
                        else
                        {
                            var LoginData = new { Message = "Неизвестный токен." };
                            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                            // Устанавливаем заголовки ответа
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "application/json";

                            response.StatusCode = 400;

                            // Возвращаем данные клиенту
                            Stream output = response.OutputStream;
                            output.Write(buffer, 0, buffer.Length);
                            output.Close();
                            response.Close();
                            continue;
                        }
                    }
                    else if (path == "/profile")
                    {
                        string token = "";
                        for (int i = 0; i < request.Headers.Count; i++)
                        {
                            string header = request.Headers.Get(i);
                            if (header.Contains("Bearer "))
                            {
                                token = header.Substring(header.IndexOf(" ") + 1);
                                break;
                            }
                        }

                        Console.WriteLine("Call profile, token: " + token);
                        List<User> TempUser = connection.Query<User>($"SELECT * FROM Users WHERE Token='{token}'").ToList();
                        if (TempUser.Count() > 0)
                        {
                            Console.WriteLine("User found");
                            RegisterData registerData = new RegisterData(TempUser[0].DecryptR(DbKey, DbIv));
                            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(registerData));

                            // Устанавливаем заголовки ответа
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "application/json";
                            response.StatusCode = 200; // Created

                            // Возвращаем данные клиенту
                            Stream output = response.OutputStream;
                            output.Write(buffer, 0, buffer.Length);
                            output.Close();
                            response.Close();
                            continue;
                        }
                        else
                        {
                            Console.WriteLine("User not found");
                            var LoginData = new { Message = "Пользователь не найден" };
                            byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                            // Устанавливаем заголовки ответа
                            response.ContentLength64 = buffer.Length;
                            response.ContentType = "application/json";

                            response.StatusCode = 401;

                            // Возвращаем данные клиенту
                            Stream output = response.OutputStream;
                            output.Write(buffer, 0, buffer.Length);
                            output.Close();
                            response.Close();
                            continue;
                        }
                    }
                }
                else if (request.HttpMethod == "PUT")
                {
                    if (path == "/changeprofile")
                    {
                        // Получение данных из тела запроса
                        var requestBody = new byte[request.ContentLength64];
                        request.InputStream.Read(requestBody, 0, requestBody.Length);
                        var newData = JsonConvert.DeserializeObject<ChangeProfileData>(Encoding.UTF8.GetString(requestBody));
                        User newUser = new User(newData);
                        newUser.Encrypt(DbKey, DbIv);

                        // Обработка данных
                        connection.Execute($"UPDATE Users SET Email='{newUser.Email}', FirstName='{newUser.FirstName}', LastName='{newUser.LastName}', Surname='{newUser.Surname}', PhoneNumber='{newUser.PhoneNumber}', Hash='{CryptoGraphy.GetHash(newData.FirstName + newData.LastName + newData.Surname + newData.Email + newData.PhoneNumber)}' WHERE Token='{newData.RefreshToken}'");

                        // Отправка ответа
                        var LoginData = new { Message = "Пользователь обновлен" };
                        byte[] buffer = System.Text.Encoding.UTF8.GetBytes(Newtonsoft.Json.JsonConvert.SerializeObject(LoginData));

                        // Устанавливаем заголовки ответа
                        response.ContentLength64 = buffer.Length;
                        response.ContentType = "application/json";

                        response.StatusCode = 200;

                        // Возвращаем данные клиенту
                        Stream output = response.OutputStream;
                        output.Write(buffer, 0, buffer.Length);
                        output.Close();
                    }
                }
                else
                {
                    response.StatusCode = 200;
                    response.StatusDescription = "Method Not Allowed";
                }

                response.Close();
            }
        }
    }
}