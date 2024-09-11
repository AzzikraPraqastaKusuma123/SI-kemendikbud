<?php
session_start();
include("inc_koneksi.php");

if (isset($_SESSION['admin_username'])) {
    header("location:admin_depan.php");
    exit();
}

$username = "";
$password = "";
$err = "";

if (isset($_POST['login'])) {
    $username   = $_POST['username'];
    $password   = $_POST['password'];

    if (empty($username) || empty($password)) {
        $err .= "<li>Silakan masukkan username dan password</li>";
    } else {
        // Gunakan prepared statement untuk mencegah SQL Injection
        $stmt = $koneksi->prepare("SELECT * FROM admin WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $r1 = $result->fetch_assoc();

        if ($r1 && password_verify($password, $r1['password'])) {
            $login_id = $r1['login_id'];

            // Ambil akses pengguna
            $stmt = $koneksi->prepare("SELECT akses_id FROM admin_akses WHERE login_id = ?");
            $stmt->bind_param("i", $login_id);
            $stmt->execute();
            $result = $stmt->get_result();
            
            while ($r2 = $result->fetch_assoc()) {
                $akses[] = $r2['akses_id']; // akses: spp, guru, siswa, dll.
            }

            if (empty($akses)) {
                $err .= "<li>Kamu tidak punya akses ke halaman admin</li>";
            } else {
                // Simpan data ke session
                $_SESSION['admin_username'] = $username;
                $_SESSION['admin_akses'] = $akses;
                header("location:admin_depan.php");
                exit();
            }
        } else {
            $err .= "<li>Akun tidak ditemukan atau password salah</li>";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <style>
    body {
        font-family: Arial, sans-serif;
        background: url('https://img.freepik.com/free-vector/geometric-green-abstract-background_23-2148373321.jpg?size=626&ext=jpg&ga=GA1.1.2008272138.1725840000&semt=ais_hybrid') no-repeat center center fixed;
        background-size: cover;
        margin: 0;
        padding: 0;
        display: flex;
        justify-content: center;
        align-items: center;
        height: 100vh;
    }

    #app {
        width: 400px;
        padding: 40px;
        background-color: rgba(255, 255, 255, 0.9);
        border-radius: 10px;
        box-shadow: 0 0 15px rgba(0, 0, 0, 0.3);
    }

    h1 {
        text-align: center;
        color: #1b5e20;
        font-size: 2em;
    }

    .input {
        width: 100%;
        padding: 15px;
        margin: 10px 0;
        border: 1px solid #c8e6c9;
        border-radius: 5px;
        box-sizing: border-box;
        font-size: 1.1em;
    }

    input[type="submit"] {
        width: 100%;
        background-color: #2e7d32;
        color: white;
        padding: 15px;
        border: none;
        border-radius: 5px;
        cursor: pointer;
        font-size: 1.1em;
        font-weight: bold;
    }

    input[type="submit"]:hover {
        background-color: #1b5e20;
    }

    ul {
        background-color: #fbe9e7;
        color: #d32f2f;
        padding: 15px;
        border-radius: 5px;
        margin-top: 20px;
        list-style: none;
    }

    @media (max-width: 600px) {
        #app {
            width: 90%;
            padding: 20px;
        }

        h1 {
            font-size: 1.5em;
        }

        .input,
        input[type="submit"] {
            font-size: 1em;
            padding: 10px;
        }
    }
    </style>
</head>

<body>
    <div id="app">
        <h1>Halaman Login</h1>
        <?php if ($err) echo "<ul>$err</ul>"; ?>
        <form action="" method="post">
            <input type="text" value="<?php echo htmlspecialchars($username); ?>" name="username" class="input"
                placeholder="Isikan Username..." /><br /><br />
            <input type="password" name="password" class="input" placeholder="Isikan Password" /><br /><br />
            <input type="submit" name="login" value="Masuk Ke Sistem" />
        </form>
    </div>
</body>

</html>