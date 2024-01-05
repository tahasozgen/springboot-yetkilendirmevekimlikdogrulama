package deneme.orneksirket.yetkilendirme.konfigurasyon;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User; 
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException; 
import org.springframework.security.web.SecurityFilterChain;

import hata.entities.somut.ArgumanBosHatasi;
import hata.entities.somut.BasarisizIslemHatasi;
import hata.service.hatafirlatici.JenerikHataFirlatici;
import yetkilendirmekimlikdogrulama.contracts.somut.mesaj.AcOturumIstek;
import yetkilendirmekimlikdogrulama.contracts.somut.mesaj.AcOturumYanit;
import yetkilendirmekimlikdogrulama.contracts.soyut.IKullaniciServis;
import yetkilendirmekimlikdogrulama.entities.enumeration.OturumNetice;

@Configuration
@EnableWebSecurity
public class GuvenlikKonfigurasyonu {

	@Autowired
	UserDetailsService userService;

	@Autowired
	IKullaniciServis kullaniciServis;

	public Authentication authenticate(Authentication parametre) throws AuthenticationException {

		User kullanici = null;

		Authentication yetkilendirme = null;

		String kullaniciAdi = parametre.getName();

		String sifre = parametre.getCredentials().toString();

		AcOturumIstek istek = new AcOturumIstek("yök", kullaniciAdi, sifre);

		AcOturumYanit yanit = kullaniciServis.acOturum(istek);

		if (yanit != null && yanit.basariliMi()) {

			if (yanit.getOturumNetice().equals(OturumNetice.KULLANICIYOK))
				throw new UsernameNotFoundException(String.format("%s kullanıcısı yok.", kullaniciAdi));
			else if (yanit.getOturumNetice().equals(OturumNetice.BASARISIZ))
				throw new BadCredentialsException("oturum açma başarısız");
			else if (yanit.getOturumNetice().equals(OturumNetice.BASARILI)) {
				kullanici = yanit.getKullanici();

				yetkilendirme = new UsernamePasswordAuthenticationToken(kullanici.getUsername(),
						kullanici.getPassword(), kullanici.getAuthorities());
			}

		}

		return yetkilendirme;

	}

	@Bean
	public UserDetailsService users() {

		try {

			return this.kullaniciServis.yaratUserDetailsService();

		} catch (BasarisizIslemHatasi hata) {

			throw hata;

		} catch (IllegalArgumentException hata) {
			throw hata;

		}

//		UserDetails user = User.builder().username("user")
//				.password("{bcrypt}$2a$12$usNXwGVA53PU17YkIdntAeTRBq/BhbTjto7YzWjTyopvP3ddDz8aS") // t1
//				.roles("USER").build();
//		UserDetails admin = User.builder().username("admin")
//				.password("{bcrypt}$2a$12$usNXwGVA53PU17YkIdntAeTRBq/BhbTjto7YzWjTyopvP3ddDz8aS") // t1
//				.roles("USER", "ADMIN").build();
//		return new InMemoryUserDetailsManager(user, admin);
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {

		return http
				.authorizeHttpRequests(configurer -> configurer.requestMatchers("/**").hasRole("ADMIN")
						.requestMatchers("/**").hasRole("USER"))

				.formLogin(configurer -> configurer.loginPage("/showMyLoginPage")
						.loginProcessingUrl("/authenticateTheUser").permitAll())

				.logout(configurer -> configurer.permitAll())

				.exceptionHandling(configurer -> configurer.accessDeniedPage("/access-denied"))

				.build();
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration)
			throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public IKullaniciServis yaratIKullaniciServis() {

		try {

			IKullaniciServis kullaniciServis = yetkilendirmekimlikdogrulama.servis.somut.BagimlilikCozumleyici
					.getirOrnek().servisIdIle(658).cozumle(IKullaniciServis.class);

			JenerikHataFirlatici.firlatBasarisizIslemHatasiBasarisizIse(kullaniciServis);

			return kullaniciServis;

		} catch (ArgumanBosHatasi hata) {

			throw hata;

		} catch (BasarisizIslemHatasi hata) {

			throw hata;

		} catch (UnsupportedOperationException hata) {

			throw hata;

		}

	}
}
