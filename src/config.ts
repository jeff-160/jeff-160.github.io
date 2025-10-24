import { defineCollection, z } from 'astro:content';

export const siteConfig = {
  name: "Jerome Lim",
  title: "Student at Hwa Chong Institution",
  description: "Portfolio website of Jerome Lim",
  accentColor: "#FFEA00",
  social: {
    email: "jerome.lim1707@gmail.com",
    linkedin: "https://www.linkedin.com/in/jerome-lim-81292a30a/",
    github: "https://github.com/jeff-160",
  },
  aboutMe:
    `I'm Jerome, a student who is passionate about computing. I started coding in Secondary 2 and fell in love with it ever since.
    <br><br>
    I'm currently interested in cybersecurity and regularly participate in CTFs. If you need a Pyjail expert hmu 🔥
    <br><br>
    Outside of computing, I like playing ShellShockers and listening to heavy metal!
    <br><br>
    Let's connect on LinkedIn!
    `,
  profileImage: "/images/pfp.jpeg",
  skills: ["Python", "JavaScript", "C++"],
  projects: [
    {
      name: "Pseudocode Interpreter",
      description:
        "A minimal pseudocode interpreter that is compliant with the H2 Computing pseudocode standard, to help my schoolmates better familiarise themselves with the syntax",
      link: "https://github.com/jeff-160/Pseudocode-Interpreter",
      skills: ["Python"],
    },
    {
      name: "CrowJS",
      description:
        "JavaScript superset that integrates C++ style macros into the language",
      link: "https://github.com/jeff-160/CrowJS",
      skills: ["C++"],
    },
    {
      name: "TempHairline",
      description:
        "Search history grabber and remote shell trojan for educational purposes",
      link: "http://github.com/jeff-160/TempHairline",
      skills: ["Python"],
    },
  ],
  experience: [
    {
      title: "CSIT Computing Scholar",
      company: "",
      dateRange: "Sept 2025 - Present",
      bullets: [],
    },
    {
      title: "Sentinel Programme",
      company: "",
      dateRange: "March 2025 - Present",
      bullets: [
        "Youth development programme by DIS",
        "Trains youths in cybersecurity to aid in Singapore's digital defence"
      ],
    },
    {
      title: "Product Development Consultant",
      company: "Sabre Asia Pacific",
      dateRange: "Nov 2024",
      bullets: [
        "3 week school attachment programme where I did full-stack dev",
        "Developer for CSL HotelAvail and HotelDetails API tools",
      ],
    },
  ],
  education: [
    {
      school: "Hwa Chong Institution",
      degree: "",
      dateRange: "2020 - Present",
      achievements: [],
    },
  ]
};

const blog = defineCollection({
  schema: z.object({
    title: z.string(),
    date: z.date(),
    description: z.string(),
    tags: z.array(z.string()).optional(),
    draft: z.boolean().optional(),
  }),
});

export const collections = { blog };