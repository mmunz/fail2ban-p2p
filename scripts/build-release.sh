# Script/helper to make a release from fail2ban-p2p svn
# Before you checkout make sure you edited the files in debian directory

# At least edit debian/changelog. Use dch -v <version>-<revision> to create a new entry

tag=0.0.5
rev=1
svn co https://svn.physik.uni-augsburg.de/svn/fail2ban-p2p/tags/$tag
mv $tag fail2ban-p2p-${tag}-${rev}
cd fail2ban-p2p-${tag}-${rev}
rm -rf `find . -type d -name .svn`
cd ..
tar -cvzf fail2ban-p2p-${tag}-${rev}.tar.gz fail2ban-p2p-${tag}-${rev}
echo "Tarball fail2ban-p2p-${tag}-${rev}.tar.gz created"

echo "Now building debian package. Use m to build a 'multiple binary' package."
cd fail2ban-p2p-${tag}-${rev}
dh_make -f ../fail2ban-p2p-${tag}-${rev}.tar.gz --addmissing || echo "Something went wrong with dh_make, please check output and retry"
dpkg-buildpackage -us -uc || echo "Something went wrong with dpkg-buildpackage, please check output and retry"

echo "Now move the .tar.gz and the .deb to releases and commit :)"

