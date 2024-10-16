package jwt.auth.controller;

import jwt.auth.model.User;
import jwt.auth.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.web.bind.annotation.*;

@RequiredArgsConstructor
@RestController
public class RestApiController {
    private final BCryptPasswordEncoder encoder;
    private final UserRepository userRepository;

    @GetMapping("/home")
    public String home() {
        return "<h1>home</h1>";
    }
    @PostMapping ("/token")
    public String token() {
        return "<h1>token</h1>";
    }

    @PostMapping("/join")
    public String join(@RequestBody User user) {
        user.setPassword(encoder.encode(user.getPassword()));
        user.setRoles("ROLE_USER");
        userRepository.save(user);
        return "<h1>회원가입끝</h1>";

    }

    @GetMapping("/api/v1/user/{path}")
    public String user(@PathVariable String path) {
        return "<h1>user</h1>";
    }
    @GetMapping("/api/v1/manager/{path}")
    public String manager(@PathVariable String path) {
        return "<h1>manager</h1>";
    }
    @GetMapping("/api/v1/admin/{path}")
    public String admin(@PathVariable String path) {
        return "<h1>admin</h1>";
    }
}
