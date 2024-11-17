import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';

import styles from './index.module.css';

export default function Home(): JSX.Element {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title={siteConfig.title}
      description="A TaskDriver plugin for HashiCorp Nomad to run IIS workloads.">

			<div className={styles.container}>
				<img className={styles.logo} />
				<h2>{siteConfig.tagline}</h2>

				<iframe src="https://github.com/sponsors/sevensolutions/button" title="Sponsor sevensolutions" height="32" width="114"></iframe>
			</div>
    </Layout>
  );
}