package com.example.todos.user;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import com.example.todos.enums.Role;
import com.example.todos.model.TodoDAO;
import jakarta.persistence.CascadeType;
import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@Entity
@Table(name = "user_details")
public class User implements UserDetails {

  /**
   * When a class implements the Serializable interface, it's recommended to provide a
   * serialVersionUID field to specify a version ID for serialization purposes.
   */
  private static final long serialVersionUID = -1952078194810925018L;


  @Id
  @GeneratedValue(strategy = GenerationType.IDENTITY)
  private Integer id;

  @Column(name = "username",nullable = false)
  private String username;
  
  @Column(name = "password",nullable = false)
  private String password;
  
  @Column(name = "email",nullable = false)
  private String email;

  @Enumerated(EnumType.STRING)
  private Role role;

  @Column(name = "firstname",nullable=false)
  private String firstName;

  @Column(name = "lastname", nullable=false)
  private String lastName;
  
  @OneToMany(mappedBy = "user", fetch = FetchType.EAGER)
  Set<TodoDAO> todos;
  
  @Override
  public boolean equals(Object o) {
    if (this == o) return true;
    if (o == null || getClass() != o.getClass()) return false;
    User user = (User) o;
    return Objects.equals(id, user.id);
  }
  
  @Override
  public int hashCode() {
    
    return Objects.hash(id);
  }

  /**
   * Functions from userdetails
   * 
   */

  @Override
  public Collection<? extends GrantedAuthority> getAuthorities() {
    return List.of(new SimpleGrantedAuthority(role.name()));
  }

  @Override
  public String getUsername() {
    return username;
  }

  @Override
  public String getPassword() {
    return password;
  }

  @Override
  public boolean isAccountNonExpired() {
    return true;
  }

  @Override
  public boolean isAccountNonLocked() {
    return true;
  }

  @Override
  public boolean isCredentialsNonExpired() {
    return true;
  }

  @Override
  public boolean isEnabled() {
    return true;
  }


}
