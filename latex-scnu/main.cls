% 定义包名
\ProvidesClass{main}
\LoadClass[a4paper]{article}

\RequirePackage[heading]{ctex} % Required for the Chinese and the corresponding section setting
\RequirePackage[includeheadfoot]{geometry} % Required for the Word-like page
\RequirePackage{fancyhdr} % Required for custom headers
\RequirePackage{setspace} % Required for the space setting
\RequirePackage{titlesec} % Required for the Chapter & Section fonts adjustment
\RequirePackage{titletoc} % Required for the Content fonts adjustment
\RequirePackage[toc,page]{appendix} % Required for the appendix environment
\RequirePackage{lastpage} % Required to determine the last page for the footer
\RequirePackage{extramarks} % Required for headers and footers
\RequirePackage{courier} % Required for the courier font
\RequirePackage{float} % Required for the Here float
\RequirePackage{graphicx} % Required to insert images
\RequirePackage{wrapfig}
\RequirePackage{booktabs} % Required for the hline of the three lines table
\RequirePackage{multirow} % Required for the multirow of table
\RequirePackage{listings} % Required for insertion of code
\RequirePackage{indentfirst} % Required for the indent before each paragraph
\RequirePackage{fontspec}
\RequirePackage{hyperref}
\RequirePackage{url}

% 添加 BibLaTeX 支持
\RequirePackage[
    backend=biber,        % 使用 biber 作为后端
    style=gb7714-2015,    % 使用符合中文标准的引用格式
    gbnamefmt=lowercase,  % 人名格式，姓在前，名在后
    gbbiblabel=bracket,   % 使用方括号作为标签
    gbalign=gb7714-2015,  % 对齐方式
    sortlocale=zh_CN,     % 中文排序
    bibencoding=utf8,     % 文献编码
    url=true,             % 支持 URL
    doi=true,             % 支持 DOI
    sorting=none          % 按引用顺序排序
]{biblatex}
% 设置参考文献字体和行距
\setlength{\bibitemsep}{0pt}
% 确保引用中的英文使用 Times New Roman
\newfontfamily\biblatinfont{Times New Roman}
% 确保中文不加粗
\renewcommand*{\mkbibnamegiven}[1]{#1}
\renewcommand*{\mkbibnamefamily}[1]{#1}
\renewcommand*{\mkbibnameprefix}[1]{#1}
\renewcommand*{\mkbibnamesuffix}[1]{#1}
% \RequirePackage{cite} % Required for the ref and cite
\RequirePackage[usenames,dvipsnames]{color} % Required for custom colors
\RequirePackage{courier} % Required for the courier font
\RequirePackage[font=footnotesize,tableposition=top]{caption} % Required for the footnote size captions of figures and tables
\RequirePackage{xcolor}
\RequirePackage[nottoc]{tocbibind}
\RequirePackage{afterpage}
\RequirePackage{enumitem}
\RequirePackage{stmaryrd} % 数学符号的包
\RequirePackage{bm} % Required for the bold in math display
\RequirePackage{amsmath} % Required for the math display
\RequirePackage{amssymb} % Required for the math display
\RequirePackage{amsbsy} % Required for the math display
\RequirePackage{cancel} % Required for the cancel symbol in math display
\RequirePackage{amsthm} % Required for the theorem edition
\RequirePackage{array} % Required for the array in math display
\RequirePackage{ifthen} % Required for the conditional commands

% 上下左右的留白
\geometry{
    top=2.5cm,
    bottom=2.5cm,
    left=2cm,
    right=2cm
} 

\lstset{
  columns=flexible,lineskip=-3pt,
  basicstyle=\small\ttfamily,
}
% 正文前的空白页
% 使用 \afterpage{\blankpage} 正文中的空白页 \afterpage{\null\newpage}
\newcommand\blankpage{
  \null
  \thispagestyle{empty}
  \addtocounter{page}{-1}
  \newpage
}
\newcommand{\ud}{\mathrm{d}} 
\makeatletter
\@addtoreset{equation}{section}
\makeatother

\renewcommand{\theequation}{\arabic{section}.\arabic{equation}}

\ctexset {
    section = {
        format={\centering \zihao {-2}\bfseries \heiti},
    },
    paragraph = {
        format={\raggedright \bfseries \zihao{-4}} 
    } 
}
\titlespacing{\section}{0em}{3em}{3em}

% Equivalent to above
\titleformat{\subsection}{\zihao{4}\bfseries \heiti}{\thesubsection}{1em}{}[]
\titlespacing{\subsection}{0em}{3em}{0em}
\titleformat{\subsubsection}{\zihao{-4}\bfseries \heiti}{\thesubsubsection}{1em}{}[]
\titlespacing{\subsubsection}{0em}{3em}{0em}

% 页头页尾设置
\newcommand{\thesistitlefancyhead}{一种多阶段密钥交换协议的设计与实现} % 定义论文题目为页眉
\pagestyle{fancy}
\fancyhf{}
\fancyhead{}
\fancyhead[C]{\thesistitlefancyhead{}} % 页眉设置为论文标题
\fancyfoot[C]{\thepage}

% 图标显示格式：图/表 <Chapter>-<Counter>:
\renewcommand{\thefigure}{\thesection-\arabic{figure}}
\renewcommand{\thetable}{\thesection-\arabic{table}}