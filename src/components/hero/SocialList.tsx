import clsx from 'clsx'
import { hero } from '@/config.json'
import { motion } from 'framer-motion'

const itemVariants = {
  hidden: {
    opacity: 0,
    y: 40,
  },
  visible: {
    opacity: 1,
    y: 0,
  },
}

export function SocialList({ className }: { className?: string }) {
  return (
    <motion.ul
      className={clsx(
        'flex gap-4 flex-wrap items-center justify-center lg:justify-start',
        className,
      )}
      initial="hidden"
      animate="visible"
      transition={{
        staggerChildren: 0.1,
      }}
    >
      {hero.socials.map((social) => (
        <motion.li key={social.name} variants={itemVariants}>
          <a
            className="relative size-9 text-white text-xl flex justify-center items-center group"
            href={social.url}
            title={social.name}
            target="_blank"
            rel="noopener noreferrer"
          >
            <span
              className="absolute inset-0 -z-1 rounded-full group-hover:scale-105 transition"
              style={{ backgroundColor: social.color }}
            ></span>
            <i className={clsx('iconfont', social.icon)} />
          </a>
        </motion.li>
      ))}
      <motion.li key="LinkedIn" variants={itemVariants}>
        <a
          className="relative size-9 text-white text-xl flex justify-center items-center group"
          href="https://www.linkedin.com/in/jerome-lim-81292a30a/"
          title="LinkedIn"
          target="_blank"
          rel="noopener noreferrer"
        >
          <span
            className="absolute inset-0 -z-1 rounded-full group-hover:scale-105 transition"
            style={{ backgroundColor: '#0A66C2' }}
          ></span>
          <svg
            xmlns="http://www.w3.org/2000/svg"
            viewBox="0 0 24 24"
            fill="currentColor"
            className="w-5 h-5"
          >
            <path d="M19 0h-14c-2.762 0-5 2.238-5 5v14c0 2.762 2.238 5 5 5h14c2.762 0 5-2.238 5-5v-14c0-2.762-2.238-5-5-5zm-11 19h-3v-10h3v10zm-1.5-11.268c-.966 0-1.75-.792-1.75-1.767s.784-1.767 1.75-1.767 1.75.792 1.75 1.767-.784 1.767-1.75 1.767zm13.5 11.268h-3v-5.5c0-1.31-.026-3-1.827-3-1.827 0-2.106 1.427-2.106 2.901v5.599h-3v-10h2.879v1.367h.041c.401-.761 1.379-1.562 2.837-1.562 3.033 0 3.593 1.996 3.593 4.59v5.605z" />
          </svg>
        </a>
      </motion.li>
    </motion.ul>
  )
}
