FROM debian:buster




RUN echo 'deb [check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes] http://snapshot.debian.org/archive/debian/20170418T214438Z/ testing main' >> /etc/apt/sources.list.d/snapshot.list

RUN echo 'deb [check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes] http://snapshot.debian.org/archive/debian/20170418T214438Z/ stable main' >> /etc/apt/sources.list.d/snapshot.list

RUN echo 'deb [check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes] http://snapshot.debian.org/archive/debian/20170418T214438Z/ unstable main' >> /etc/apt/sources.list.d/snapshot.list


RUN apt-get update

RUN apt-get install -y --allow-unauthenticated --allow-downgrades --fix-missing aptitude nano adduser

RUN DEBIAN_FRONTEND=non-interactive aptitude -y --allow-untrusted -o Aptitude::ProblemResolver::SolutionCost='100*canceled-actions,200*removals' install opensmtpd=6.0.2p1-2



ARG USERNAME=toto
ARG PASSWORD=toto
RUN useradd -m ${USERNAME} -s /bin/bash && printf "${PASSWORD}\n${PASSWORD}\n" | passwd ${USERNAME} 2> /dev/null


