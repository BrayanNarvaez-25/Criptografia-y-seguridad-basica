package com.krakedev.jwt.services;

import java.util.Optional;

import org.mindrot.jbcrypt.BCrypt;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.krakedev.jwt.entidades.Usuario;
import com.krakedev.jwt.repositories.UsuarioRepository;

@Service
public class UsuarioService {

    @Autowired
    private UsuarioRepository usuarioRepository;

    // HITO 1 — vulnerable (texto plano)
//    public Usuario registrar(Usuario usuario) {
//        return usuarioRepository.save(usuario);
//    }
//
//    public Optional<Usuario> login(String username, String password) {
//        Optional<Usuario> usuario = usuarioRepository.findByUsername(username);
//        if (usuario.isPresent() && usuario.get().getPassword().equals(password)) {
//            return usuario;
//        }
//        return Optional.empty();
//    }
 // HITO 2 — con BCrypt
    public Usuario registrar(Usuario usuario) {
        usuario.setPassword(BCrypt.hashpw(usuario.getPassword(), BCrypt.gensalt()));
        return usuarioRepository.save(usuario);
    }

    public Optional<Usuario> login(String username, String password) {
        Optional<Usuario> usuario = usuarioRepository.findByUsername(username);
        if (usuario.isPresent() && BCrypt.checkpw(password, usuario.get().getPassword())) {
            return usuario;
        }
        return Optional.empty();
    }
}