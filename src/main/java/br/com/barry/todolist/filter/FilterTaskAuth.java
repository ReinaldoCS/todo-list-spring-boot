package br.com.barry.todolist.filter;

import java.io.IOException;
import java.util.Base64;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import at.favre.lib.crypto.bcrypt.BCrypt;
import br.com.barry.todolist.user.IUserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class FilterTaskAuth extends OncePerRequestFilter {

  @Autowired
  private IUserRepository userRepository;

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
      throws ServletException, IOException {

    // var servletPath = request.getServletPath();
    var servletPath = request.getServletPath();

    if (servletPath.startsWith("/tasks/")) {

      // Pegar a autenticação (usuário e senha)
      var authorization = request.getHeader("Authorization");

      var authEncoded = authorization.substring("Basic".length()).trim();
      // System.out.println("authEncoded: " + authEncoded);

      byte[] authDecode = Base64.getDecoder().decode(authEncoded);
      // System.out.println("authDecode: " + authDecode);

      var authString = new String(authDecode, "UTF-8");
      // System.out.println("authString: " + authString);

      String[] credentials = authString.split(":");

      String username = credentials[0];
      // System.out.println("username: " + username);

      String password = credentials[1];
      // System.out.println("password: " + password);

      // Valiar usuário

      var userHasBeenExisted = this.userRepository.findByUsername(username);

      if (userHasBeenExisted == null) {
        response.sendError(401);
      } else {
        var passwordVerify = BCrypt.verifyer().verify(password.toCharArray(), userHasBeenExisted.getPassword());

        // Validar senha
        if (passwordVerify.verified) {
          filterChain.doFilter(request, response);
        } else {
          response.sendError(401);
        }
      }
    } else {
      filterChain.doFilter(request, response);
    }

  }

}
