FROM debian:jessie


RUN echo -n "" > /etc/apt/sources.list



RUN echo 'deb [check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes] http://snapshot.debian.org/archive/debian/20160118T040946Z/ testing main' >> /etc/apt/sources.list.d/snapshot.list

RUN echo 'deb [check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes] http://snapshot.debian.org/archive/debian/20160118T040946Z/ stable main' >> /etc/apt/sources.list.d/snapshot.list

RUN echo 'deb [check-valid-until=no allow-insecure=yes allow-downgrade-to-insecure=yes] http://snapshot.debian.org/archive/debian/20160118T040946Z/ unstable main' >> /etc/apt/sources.list.d/snapshot.list


RUN apt-get update

RUN apt-get install -y --force-yes --fix-missing aptitude nano adduser

RUN DEBIAN_FRONTEND=non-interactive aptitude -y --allow-untrusted -o Aptitude::ProblemResolver::SolutionCost='100*canceled-actions,200*removals' install imagemagick=8:6.8.9.9-7



ARG USERNAME=toto
ARG PASSWORD=toto
RUN useradd -m ${USERNAME} -s /bin/bash && printf "${PASSWORD}\n${PASSWORD}\n" | passwd ${USERNAME} 2> /dev/null


