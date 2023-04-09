using Dapper;
using System;
using System.Collections.Generic;
using System.Data.SQLite;
using System.Linq;
using System.Reflection;
using System.Security.Policy;
using System.Text;
using System.Threading.Tasks;

namespace Backend
{
    public class BlockchainUser
    {
        public int Id { get; set; }
        public string Login { get; set; }
        public string Password { get; set; }

        public BlockchainUser()
        {

        }

        public BlockchainUser(string login, string password)
        {
            Login = login;
            Password = password;
        }
    }

    public class LoginData
    {
        public string Email { get; set; }
        public string Password { get; set; }

        LoginData()
        {

        }

        LoginData(string email, string password)
        {
            Email = email;
            Password = password;
        }
    }

    public class Tokens
    {
        public string RefreshToken { get; set; }

        public Tokens()
        {

        }

        public Tokens(string refresh)
        {
            RefreshToken = refresh;
        }
    }

    public class RegisterData
    {
        public string Email { get; set; }
        public string Password { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Surname { get; set; }
        public string PhoneNumber { get; set; }

        RegisterData()
        {

        }

        public RegisterData(string email, string password, string firstName, string lastName, string surname, string phoneNumber)
        {
            Email = email;
            Password = password;
            FirstName = firstName;
            LastName = lastName;
            Surname = surname;
            PhoneNumber = phoneNumber;
        }

        public RegisterData(User user)
        {
            FirstName = user.FirstName;
            LastName = user.LastName;
            Surname = user.Surname;
            Email = user.Email;
            PhoneNumber = user.PhoneNumber;
            Password = null;
        }
    }

    public class ChangeProfileData
    {
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Surname { get; set; }
        public string PhoneNumber { get; set; }
        public string RefreshToken { get; set; }

        ChangeProfileData()
        {

        }

        public ChangeProfileData(string email, string firstName, string lastName, string surname, string phoneNumber, string token)
        {
            Email = email;
            FirstName = firstName;
            LastName = lastName;
            Surname = surname;
            PhoneNumber = phoneNumber;
            RefreshToken = token;
        }
    }

    public class User
    {
        public int Id { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }
        public string Surname { get; set; }
        public string Email { get; set; }
        public string PhoneNumber { get; set; }
        public string Token { get; set; }
        public string Hash { get; set; }

        public User()
        {

        }

        public User(RegisterData registerData)
        {
            FirstName = registerData.FirstName;
            LastName = registerData.LastName;
            Surname = registerData.Surname;
            Email = registerData.Email;
            PhoneNumber = registerData.PhoneNumber;
            Hash = CryptoGraphy.GetHash(FirstName + LastName + Surname + Email + PhoneNumber);
        }

        public User(ChangeProfileData data)
        {
            Email = data.Email;
            FirstName = data.FirstName;
            LastName = data.LastName;
            Surname = data.Surname;
            PhoneNumber = data.PhoneNumber;
            Hash = CryptoGraphy.GetHash(data.FirstName + data.LastName + data.Surname + data.Email + data.PhoneNumber);
        }

        public void ValidData(ChangeProfileData data)
        {
            Email = data.Email;
            FirstName = data.FirstName;
            LastName = data.LastName;
            Surname = data.Surname;
            PhoneNumber = data.PhoneNumber;
            Hash = CryptoGraphy.GetHash(FirstName + LastName + Surname + Email + PhoneNumber);
        }

        public void Encrypt(byte[] key, byte[] iv)
        {
            FirstName = CryptoGraphy.EncryptStringToBytesString_Aes(FirstName, key, iv);
            LastName = CryptoGraphy.EncryptStringToBytesString_Aes(LastName, key, iv);
            Surname = CryptoGraphy.EncryptStringToBytesString_Aes(Surname, key, iv);
            Email = CryptoGraphy.EncryptStringToBytesString_Aes(Email, key, iv);
            PhoneNumber = CryptoGraphy.EncryptStringToBytesString_Aes(PhoneNumber, key, iv);
        }

        public void Decrypt(byte[] key, byte[] iv)
        {
            FirstName = CryptoGraphy.DecryptStringFromBytesString_Aes(FirstName, key, iv);
            LastName = CryptoGraphy.DecryptStringFromBytesString_Aes(LastName, key, iv);
            Surname = CryptoGraphy.DecryptStringFromBytesString_Aes(Surname, key, iv);
            Email = CryptoGraphy.DecryptStringFromBytesString_Aes(Email, key, iv);
            PhoneNumber = CryptoGraphy.DecryptStringFromBytesString_Aes(PhoneNumber, key, iv);
        }

        public User DecryptR(byte[] key, byte[] iv)
        {
            User newUser = new User();
            newUser.FirstName = CryptoGraphy.DecryptStringFromBytesString_Aes(FirstName, key, iv);
            newUser.LastName = CryptoGraphy.DecryptStringFromBytesString_Aes(LastName, key, iv);
            newUser.Surname = CryptoGraphy.DecryptStringFromBytesString_Aes(Surname, key, iv);
            newUser.Email = CryptoGraphy.DecryptStringFromBytesString_Aes(Email, key, iv);
            newUser.PhoneNumber = CryptoGraphy.DecryptStringFromBytesString_Aes(PhoneNumber, key, iv);
            return newUser;
        }

        public bool CheckHash()
        {
            return CryptoGraphy.GetHash(FirstName + LastName + Surname + Email + PhoneNumber) == Hash;
        }

        public static void ConstructTable(SQLiteConnection connection)
        {
            connection.Execute(@"CREATE TABLE IF NOT EXISTS Users (
            Id INTEGER PRIMARY KEY, 
            FirstName TEXT, 
            LastName TEXT, 
            Surname TEXT, 
            Email TEXT,
            PhoneNumber TEXT,
            Token TEXT,
            Hash TEXT
            )");
        }

        public static void InsertUser(SQLiteConnection connection, User user, byte[] key, byte[] iv)
        {
            connection.Execute("INSERT INTO Users (FirstName, LastName, Surname, Email, PhoneNumber, Token, Hash) VALUES (@FirstName, @LastName, @Surname, @Email, @PhoneNumber, @Token, @Hash)", user);
        }

        public static void GetAllUsers(SQLiteConnection connection, out IEnumerable<User> users, byte[] key, byte[] iv)
        {
            users = connection.Query<User>("SELECT * FROM Users");

            foreach (User user in users)
                user.Decrypt(key, iv);
        }

        public static User LoginUser(Blockchain blockchain, List<User> users, string email, string password)
        {
            User UserByEmail = users.FirstOrDefault(p => p.Email == email);
            if (UserByEmail != null)
            {
                string password_hash = Block.CalculateHash(password, blockchain.Chain[UserByEmail.Id - 1].Hash);
                if (password_hash == blockchain.Chain[UserByEmail.Id].Hash)
                    return UserByEmail;
            }
            return null;
        }
    }
}
